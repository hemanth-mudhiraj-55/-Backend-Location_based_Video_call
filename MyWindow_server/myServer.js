const express = require('express');
const twilio = require('twilio');
const { MongoClient, ObjectId } = require('mongodb');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const tls = require('tls');
const https = require('https');
const { body, validationResult } = require('express-validator');

const rateLimit = require('express-rate-limit');

dotenv.config();

const winston = require('winston');
const path = require('path');
const { format, transports } = winston;

// Custom filter format for location logs
const locationFilter = format((info, opts) => {
  return info.service === 'location' ? info : false;
});

// Configure Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  transports: [
    // Error logs (only errors)
    new transports.File({ 
      filename: path.join(__dirname, 'logs', 'error.log'), 
      level: 'error' 
    }),
    
    // Combined logs (all levels)
    new transports.File({ 
      filename: path.join(__dirname, 'logs', 'combined.log') 
    }),
    
    // Location-specific logs (filtered)
    new transports.File({
      filename: path.join(__dirname, 'logs', 'locations.log'),
      level: 'info',
      format: format.combine(
        locationFilter(),
        format.json()
      )
    }),
    
    // Console output
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.simple()
      )
    })
  ]
});

// Handle uncaught exceptions
logger.exceptions.handle(
  new transports.File({ 
    filename: path.join(__dirname, 'logs', 'exceptions.log') 
  })
);

module.exports = logger;

// Create a rotating file transport for daily logs
if (process.env.NODE_ENV === 'production') {
    logger.add(new winston.transports.File({
        filename: path.join(__dirname, 'logs', 'application.log'),
        maxsize: 5242880, // 5MB
        maxFiles: 5
    }));
}

const app = express();
const url = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const dbName = 'MyWindow';
const JWT_SECRET = process.env.JWT_SECRET || 'Top_Secret';

// Rate limiting configuration
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later'
});

// Twilio credentials
const accountSid = process.env.TWILIO_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = new twilio(accountSid, authToken);

app.use(express.json());

let db;
let otpStore = {
    email: {},
    mobile: {},
    resetTokens: {}
};

// Create a custom agent to ignore self-signed certificate errors
const customAgent = new https.Agent({
    rejectUnauthorized: false
});

// Connect to MongoDB
async function connectDB() {
    try {
        const client = await MongoClient.connect(url, {
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            maxPoolSize: 50,
            retryWrites: true,
            retryReads: true
        });
        db = client.db(dbName);
        logger.info('Connected to MongoDB');

         // === ADD THIS === //
         await db.collection('user_locations').createIndexes([
            { key: { userId: 1 } },
            { key: { location: "2dsphere" } }, // For geospatial queries
            { key: { timestamp: -1 } } // For sorting by recent
        ]);
        // ================ //

    } catch (error) {
        logger.error('Error while connecting to MongoDB:', error);
        process.exit(1);
    }
}

// Utility functions
const sendSMS = async (name, mobile, mOTP) => {
    const body = `Dear ${name}, ${mOTP} is the OTP to validate your mobile number for MyWindow Application.`;
    const msgOptions = {
        from: process.env.TWILIO_PHONE,
        to: mobile,
        body
    };

    try {
        const message = await client.messages.create(msgOptions);
        logger.info(`SMS sent to ${mobile}: ${message.sid}`);
        return true;
    } catch (error) {
        logger.error(`Error sending SMS to ${mobile}: ${error.message}`);
        throw new Error('Failed to send SMS');
    }
};

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false
    },
    secure: false,
    requireTLS: true,
    connectionTimeout: 10000,
    socketTimeout: 10000,
    // Remove or modify these logging options:
    // logger: true,
    // debug: true,
    logger: process.env.NODE_ENV !== 'production', // Only log in non-production
    debug: process.env.NODE_ENV === 'development' // Only debug in development
});

const sendEmailOTP = async (email, name, emailOtp) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'OTP for Mail verification in MyWindow application',
        text: `Dear ${name},
            \n${emailOtp} is the OTP to validate your e-mail id for MyWindow Application
                            
            \nNOTE: This is a system-generated email. Please do not reply to it.
                            
            \nRegards,
            \nHelpdesk MyWindow.`,
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        logger.info(`Email OTP sent to ${email}: ${info.response}`);
        return info;
    } catch (error) {
        logger.error(`Error sending email to ${email}: ${error.message}`);
        throw new Error('Failed to send email');
    }
};

// Authentication middleware
const authenticate = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        logger.warn('Authentication attempt without token');
        return res.status(401).json({ 
            success: false,
            error: "Authorization token required" 
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await db.collection('registration').findOne({ 
            _id: new ObjectId(decoded.userId) 
        });
        
        if (!user) {
            logger.warn(`User not found for token: ${token}`);
            return res.status(401).json({ 
                success: false,
                error: "User not found" 
            });
        }
        
        req.user = user;
        logger.info(`User authenticated: ${user.email}`);
        next();
    } catch (error) {
        logger.error(`JWT verification error: ${error.message}`);
        res.status(401).json({ 
            success: false,
            error: "Invalid token" 
        });
    }
};

// Registration endpoints
app.post('/Registration/Confirm', async (req, res) => {
    console.log("Registration/Confirm request received");
    try {
        if (!db) {
            console.error(" Database is not connected");
            return res.status(500).send({ 
                success: false,
                message: "Database connection error" 
            });
        }

        const { uid, email, mobile, name } = req.body;
        console.log(uid,email,mobile,name)

        // ===== Input Validation =====
        // 1. Check UID
        if (!/^[a-zA-Z0-9_.]{3,30}$/.test(uid)) {
            console.warn(` Registration Credentials Manipulated (Invalid UID): ${uid}`);
            return res.status(400).send({
                success: false,
                message: "Invalid User ID. Use 3-30 chars (letters, numbers, _ and . allowed)."
            });
        }

        // 2. Check Name
        if (!name || name.length > 30) {
            console.warn(` Registration Credentials Manipulated (Invalid Name): ${name}`);
            return res.status(400).send({
                success: false,
                message: "Invalid Full Name. Max 30 characters allowed."
            });
        }

        // 3. Check Email
        if (!/^[a-zA-Z0-9._%+-]+@(gmail\.com|yahoo\.com|outlook\.com|curaj\.ac\.in)$/.test(email)) {
            console.warn(` Registration Credentials Manipulated (Invalid Email): ${email}`);
            return res.status(400).send({
                success: false,
                message: "Invalid Email. Use Gmail, Yahoo, Outlook, or Curaj email."
            });
        }

        // 4. Check Mobile
        if (!/^(\+91|91)?[6-9]\d{9}$/.test(mobile)) {
            console.warn(`Registration Credentials Manipulated (Invalid Mobile): ${mobile}`);
            return res.status(400).send({
                success: false,
                message: "Invalid Mobile Number. Use a valid Indian mobile number with or without country code (+91XXXXXXXXXX or 91XXXXXXXXXX)."
            });
        }
        

        // ===== Database Check =====
        const collection = db.collection('registration');
        const existingUser = await collection.findOne({
            $or: [{ email }, { mobile }, { uid }]
        });

        if (existingUser) {
            console.warn(` Duplicate Registration Attempt (UID/Email/Mobile already exists): ${uid}`);
            return res.status(400).send({ 
                success: false,
                message: "User already registered (email, mobile, or UID exists)." 
            });
        }

        // ===== OTP Generation & Sending =====
        const emailOtp = Math.floor(100000 + Math.random() * 900000);
        const mobileOtp = Math.floor(100000 + Math.random() * 900000);

        otpStore.email = otpStore.email || {};
        otpStore.mobile = otpStore.mobile || {};

        otpStore.email[email] = {
            otp: emailOtp,
            expiresAt: Date.now() + 300000 // 5 minutes
        };

        otpStore.mobile[mobile] = {
            otp: mobileOtp,
            expiresAt: Date.now() + 300000 // 5 minutes
        };

        console.log(` OTPs generated for UID: ${uid} (Email: ${emailOtp}, Mobile: ${mobileOtp})`);
        
        try {
            await Promise.all([
                sendEmailOTP(email, name, emailOtp),
                sendSMS(name, mobile, mobileOtp)
            ]);
        } catch (error) {
            console.error('Error sending OTPs:', error);
            return res.status(500).send({ 
                success: false,
                message: 'Error sending OTPs. Please try again.' 
            });
        }

        res.status(200).send({ 
            success: true,
            message: 'OTPs sent successfully. Please verify.' 
        });

    } catch (error) {
        console.error(' Critical Error in /Registration/Confirm:', error);
        res.status(500).send({ 
            success: false,
            message: 'Internal server error' 
        });
    }
});

app.post('/Registration/Submit', [
    // Input validation middleware
    body('email_otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits'),
    body('mobile_otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits'),
    body('uid').isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_.]+$/).withMessage('Invalid UID format'),
    body('name').trim().isLength({ min: 1, max: 30 }).withMessage('Name must be 1-30 characters'),
    body('email').isEmail().withMessage('Invalid email format'),
    body('mobile').matches(/^(\+91|91)?[6-9]\d{9}$/).withMessage('Invalid Indian mobile number'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('gender').isIn(['Male', 'Female', 'Other', 'Prefer not to say']).withMessage('Invalid gender'),
    body('profile_pic').optional().isURL().withMessage('Invalid profile picture URL')
], async (req, res) => {
    try {
        // Check validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }

        if (!db) {
            return res.status(500).json({ 
                success: false,
                message: 'Database connection error',
                code: 'DB_CONNECTION_ERROR'
            });
        }

        const { 
            email_otp, 
            mobile_otp, 
            uid, 
            name, 
            email, 
            mobile, 
            password, 
            gender, 
            profile_pic 
        } = req.body;

        // Verify OTPs
        const emailOtpData = otpStore.email[email];
        const mobileOtpData = otpStore.mobile[mobile];

        if (!emailOtpData || !mobileOtpData) {
            return res.status(400).json({ 
                success: false,
                message: 'OTP verification required',
                code: 'OTP_VERIFICATION_REQUIRED'
            });
        }
    
        if (String(emailOtpData.otp) !== String(email_otp) || String(mobileOtpData.otp) !== String(mobile_otp)) {
            return res.status(401).json({ 
                success: false,
                message: 'Invalid OTPs',
                code: 'INVALID_OTP'
            });
        }

        if (Date.now() > emailOtpData.expiresAt || Date.now() > mobileOtpData.expiresAt) {
            delete otpStore.email[email];
            delete otpStore.mobile[mobile];
            return res.status(401).json({ 
                success: false,
                message: 'OTPs have expired',
                code: 'OTP_EXPIRED'
            });
        }

        // Clear OTPs
        delete otpStore.email[email];
        delete otpStore.mobile[mobile];

        // Check for existing user in transaction
        const session = db.client.startSession();
        let userExists = false;
        
        try {
            const usersCollection = db.collection('users');
            
            // Check for existing user
            const existingUser = await usersCollection.findOne({
                $or: [
                    { email: email.toLowerCase() },
                    { mobile },
                    { uid }
                ]
            });
        
            if (existingUser) {
                const conflicts = [];
                if (existingUser.email === email.toLowerCase()) conflicts.push('email');
                if (existingUser.mobile === mobile) conflicts.push('mobile');
                if (existingUser.uid === uid) conflicts.push('uid');
                
                return res.status(409).json({
                    success: false,
                    message: 'User already exists',
                    conflicts,
                    code: 'USER_EXISTS'
                });
            }

            console.log(password)
        
            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);

            const usersRegistration_data = db.collection('registration');
            const newDetails={
                uid,
                email :email.toLowerCase(),
                mobile,
                password: hashedPassword


            };
        
            // Create user document
            const newUser = {
                uid,
                name,
                email: email.toLowerCase(),
                mobile,
                password: hashedPassword,
                gender: gender.toLowerCase(),
                profile_pic: profile_pic || null,
                createdAt: new Date(),
                updatedAt: new Date(),
                lastLogin: null
            };
        
            const insertResult = await usersCollection.insertOne(newUser);
            const insertRegistration_Data = await usersRegistration_data.insertOne(newDetails);
        
            // Generate JWT token
            const token = jwt.sign(
                { 
                    userId: insertResult.insertedId.toString(),
                    email: newUser.email,
                    uid: newUser.uid
                },
                JWT_SECRET,
                { expiresIn: '1h' }
            );
        
            return res.status(201).json({
                success: true,
                message: 'Registration successful',
                token,
                user: {
                    uid: newUser.uid,
                    name: newUser.name,
                    email: newUser.email,
                    mobile: newUser.mobile,
                    profile_pic: newUser.profile_pic,
                    gender: newUser.gender,
                    createdAt: newUser.createdAt
                }
            });
        
        } catch (error) {
            if (error.status === 409) {
                return res.status(409).json({
                    success: false,
                    message: error.message,
                    conflicts: error.conflicts
                });
            }
            throw error;
        } finally {
            await session.endSession();
        }
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            code: 'INTERNAL_SERVER_ERROR'
        });
    }
});

// OTP Resend Endpoint
app.post('/Resend/EmailOTP', async (req, res) => {
    try {
        const { email, mobile } = req.body;
        
        if (!email && !mobile) {
            return res.status(400).json({
                success: false,
                message: 'Email or mobile required',
                code: 'MISSING_IDENTIFIER'
            });
        }

        // Check if we have previous OTP data
        let otpData = null;
        if (email && otpStore.email[email]) {
            otpData = otpStore.email[email];
        } else if (mobile && otpStore.mobile[mobile]) {
            otpData = otpStore.mobile[mobile];
        } else {
            return res.status(400).json({
                success: false,
                message: 'No pending registration found',
                code: 'NO_PENDING_REGISTRATION'
            });
        }

        // Generate new OTPs
        const newEmailOtp = Math.floor(100000 + Math.random() * 900000);
        const newMobileOtp = Math.floor(100000 + Math.random() * 900000);

        // Update OTP store
        if (email) {
            otpStore.email[email] = {
                ...otpData,
                otp: newEmailOtp,
                expiresAt: Date.now() + 300000
            };
        }

        if (mobile) {
            otpStore.mobile[mobile] = {
                ...otpData,
                otp: newMobileOtp,
                expiresAt: Date.now() + 300000
            };
        }

        // Send OTPs (mock implementation)
        if (email) {
            console.log(`[Mock] New Email OTP sent to ${email}: ${newEmailOtp}`);
        }
        if (mobile) {
            console.log(`[Mock] New SMS OTP sent to ${mobile}: ${newMobileOtp}`);
        }

        res.status(200).json({
            success: true,
            message: 'New OTPs sent successfully',
            otpExpiry: 300
        });

    } catch (error) {
        console.error('OTP resend error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            code: 'INTERNAL_SERVER_ERROR'
        });
    }
});



app.post('/Login/next', [
    body('uid').optional().isLength({ min: 3, max: 30 }),
    body('email').optional().isEmail(),
    body('Encrypted_password').isLength({ min: 1 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.warn('Validation errors in /Login/next', { errors: errors.array() });
        return res.status(400).json({
            success: false,
            errors: errors.array()
        });
    }

    try {
        if (!db) {
            logger.error('Database connection not established');
            return res.status(500).json({ 
                success: false,
                message: 'Database connection error',
                code: 'DB_ERROR'
            });
        }

        const { uid, email, Encrypted_password } = req.body;
        const collection = db.collection('registration');

        // Build query based on provided identifier
        const query = {};
        if (uid) query.uid = uid;
        if (email) query.email = email.toLowerCase();

        const user = await collection.findOne(query);
        
        if (!user) {
            logger.warn(`Login attempt for non-existent user: ${email || uid}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        // Password verification
        const isMatch = await bcrypt.compare(Encrypted_password, user.password);
        if (!isMatch) {
            logger.warn(`Invalid password attempt for user: ${user.email}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        // Generate and store OTP
        const emailOtp = Math.floor(100000 + Math.random() * 900000);
        otpStore.email[user.email] = {
            otp: emailOtp,
            userId: user._id.toString(), // Store as string to avoid conversion issues
            expiresAt: Date.now() + 300000, // 5 minutes
            loginAttempt: true
        };

        await sendEmailOTP(user.email, user.name, emailOtp);

        logger.info(`OTP sent for login to: ${user.email}`);
        res.status(200).json({
            success: true,
            message: 'OTP sent successfully',
            email: user.email,
            name: user.name
        });

    } catch (error) {
        logger.error(`Login/next error: ${error.message}`, { stack: error.stack });
        res.status(500).json({ 
            success: false,
            message: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
});

app.post('/Login/next2', [
    body('email').isEmail(),
    body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            errors: errors.array()
        });
    }

    try {
        const { email, otp } = req.body;
        const otpRecord = otpStore.email[email];

        // Validate OTP record
        if (!otpRecord || !otpRecord.loginAttempt) {
            logger.warn(`Invalid OTP attempt for: ${email}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid OTP request',
                code: 'INVALID_OTP_REQUEST'
            });
        }

        // Check expiration
        if (Date.now() > otpRecord.expiresAt) {
            delete otpStore.email[email];
            logger.warn(`Expired OTP attempt for: ${email}`);
            return res.status(401).json({
                success: false,
                message: 'OTP has expired',
                code: 'OTP_EXPIRED'
            });
        }

        // Verify OTP
        if (parseInt(otp) !== otpRecord.otp) {
            logger.warn(`Incorrect OTP attempt for: ${email}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid OTP',
                code: 'INVALID_OTP'
            });
        }

        // Get user from database using the stored userId
        const collection = db.collection('registration');
        const user = await collection.findOne({ 
            _id: new ObjectId(otpRecord.userId) 
        });

        if (!user) {
            logger.error(`User not found during OTP verification: ${otpRecord.userId}`);
            return res.status(404).json({
                success: false,
                message: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                userId: user._id.toString(),
                email: user.email,
                uid: user.uid,
                role: user.role || 'user',
                iss: 'MyWindowAPI',
                aud: 'MyWindowClient'
            },
            JWT_SECRET,
            { 
                expiresIn: '1h',
                algorithm: 'HS256'
            }
        );

        // Clean up OTP and update last login
        delete otpStore.email[email];
        await collection.updateOne(
            { _id: user._id },
            { $set: { lastLogin: new Date() } }
        );

        logger.info(`Successful login for: ${user.email}`);

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token: token,
            user: {
                name: user.name,
                email: user.email,
                uid: user.uid,
                mobile: user.mobile,
                profile_pic: user.profile_pic,
                role: user.role || 'user'
            }
        });

    } catch (error) {
        logger.error(`Login/next2 error: ${error.message}`, { stack: error.stack });
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
});
// Enhanced Password Reset Endpoints
app.post('/Login/next3', [
    body('Forget_email').isEmail(),
    body('Forget_mobile').matches(/^(\+91|91)?[6-9]\d{9}$/)
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            errors: errors.array()
        });
    }

    try {
        const { Forget_email, Forget_mobile } = req.body;
        const collection = db.collection('registration');

        // Find user with email and mobile
        const user = await collection.findOne({
            email: Forget_email.toLowerCase(),
            mobile: Forget_mobile
        });

        if (!user) {
            logger.warn(`Password reset attempt for unknown user: ${Forget_email}`);
            return res.status(404).json({
                success: false,
                message: 'No account found with this email and mobile combination',
                code: 'USER_NOT_FOUND'
            });
        }

        // Generate OTPs with rate limiting
        const now = Date.now();
        if (otpStore.resetTokens[Forget_email] && 
            otpStore.resetTokens[Forget_email].attempts >= 3 &&
            now < otpStore.resetTokens[Forget_email].nextAttempt) {
            
            const retryAfter = Math.ceil(
                (otpStore.resetTokens[Forget_email].nextAttempt - now) / 1000
            );
            
            return res.status(429).json({
                success: false,
                message: 'Too many attempts. Please try again later.',
                retryAfter: retryAfter
            });
        }

        const emailOtp = Math.floor(100000 + Math.random() * 900000);
        const mobileOtp = Math.floor(100000 + Math.random() * 900000);

        // Store OTPs with attempt tracking
        otpStore.email[Forget_email] = {
            otp: emailOtp,
            mobile: Forget_mobile,
            expiresAt: now + 300000, // 5 minutes
            purpose: 'password_reset'
        };
        
        otpStore.mobile[Forget_mobile] = {
            otp: mobileOtp,
            email: Forget_email,
            expiresAt: now + 300000,
            purpose: 'password_reset'
        };

        // Track reset attempts
        if (!otpStore.resetTokens[Forget_email]) {
            otpStore.resetTokens[Forget_email] = {
                attempts: 1,
                nextAttempt: now + 3600000 // 1 hour after 3 attempts
            };
        } else {
            otpStore.resetTokens[Forget_email].attempts += 1;
        }

        // Send OTPs in parallel
        await Promise.all([
            sendEmailOTP(Forget_email, user.name, emailOtp),
            sendSMS(user.name, Forget_mobile, mobileOtp)
        ]);

        logger.info(`Password reset OTPs sent to: ${Forget_email}`);

        res.status(200).json({
            success: true,
            message: 'OTPs sent successfully',
            expiresIn: 300 // 5 minutes
        });

    } catch (error) {
        logger.error(`Login/next3 error: ${error.message}`, { stack: error.stack });
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
});

app.post('/Login/next4', [
    body('Forget_Mobile_OTP').isLength({ min: 6, max: 6 }),
    body('Forget_Email_OTP').isLength({ min: 6, max: 6 }),
    body('Forget_Mobile').matches(/^(\+91|91)?[6-9]\d{9}$/),
    body('Forget_Email').isEmail()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            errors: errors.array()
        });
    }

    try {
        const { 
            Forget_Mobile_OTP, 
            Forget_Email_OTP,
            Forget_Mobile,
            Forget_Email
        } = req.body;

        // Get OTP records
        const emailOtpData = otpStore.email[Forget_Email];
        const mobileOtpData = otpStore.mobile[Forget_Mobile];
        
        if (!emailOtpData || !mobileOtpData || 
            emailOtpData.purpose !== 'password_reset' || 
            mobileOtpData.purpose !== 'password_reset') {
            
            logger.warn(`Invalid OTP verification attempt for: ${Forget_Email}`);
            return res.status(401).json({
                success: false,
                message: 'OTP verification session not found or invalid',
                code: 'INVALID_OTP_SESSION'
            });
        }

        // Check if email and mobile match
        if (emailOtpData.mobile !== Forget_Mobile || 
            mobileOtpData.email !== Forget_Email) {
            
            logger.warn(`OTP mismatch for email: ${Forget_Email} and mobile: ${Forget_Mobile}`);
            return res.status(401).json({
                success: false,
                message: 'Email and mobile combination mismatch',
                code: 'IDENTIFIER_MISMATCH'
            });
        }

        // Check expiration
        if (Date.now() > emailOtpData.expiresAt || 
            Date.now() > mobileOtpData.expiresAt) {
            
            delete otpStore.email[Forget_Email];
            delete otpStore.mobile[Forget_Mobile];
            
            logger.warn(`Expired OTP attempt for: ${Forget_Email}`);
            return res.status(401).json({
                success: false,
                message: 'OTPs have expired',
                code: 'OTP_EXPIRED'
            });
        }

        // Verify OTPs
        if (parseInt(Forget_Email_OTP) !== emailOtpData.otp || 
            parseInt(Forget_Mobile_OTP) !== mobileOtpData.otp) {
            
            logger.warn(`Incorrect OTPs provided for: ${Forget_Email}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid OTPs',
                code: 'INVALID_OTP'
            });
        }

        // Get user
        const user = await db.collection('registration').findOne({ 
            email: Forget_Email.toLowerCase(),
            mobile: Forget_Mobile
        });

        if (!user) {
            logger.error(`User not found during OTP verification: ${Forget_Email}`);
            return res.status(404).json({
                success: false,
                message: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        // Generate secure reset token (15 minutes)
        const resetToken = jwt.sign(
            { 
                userId: user._id.toString(),
                action: 'password_reset',
                email: user.email,
                iss: 'MyWindowAPI',
                aud: 'MyWindowClient'
            },
            JWT_SECRET,
            { 
                expiresIn: '15m',
                algorithm: 'HS256'
            }
        );

        // Store reset token with expiration
        otpStore.resetTokens[resetToken] = {
            userId: user._id.toString(),
            expiresAt: Date.now() + 900000 // 15 minutes
        };

        // Clean up OTPs
        delete otpStore.email[Forget_Email];
        delete otpStore.mobile[Forget_Mobile];

        logger.info(`Password reset token generated for: ${user.email}`);

        res.status(200).json({
            success: true,
            message: 'OTP verification successful',
            resetToken: resetToken,
            expiresIn: 900 // 15 minutes
        });

    } catch (error) {
        logger.error(`Login/next4 error: ${error.message}`, { stack: error.stack });
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
});

// Enhanced Password Reset Endpoint
app.post('/Login/Password_changed', [
    body('resetToken').isJWT(),
    body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            errors: errors.array()
        });
    }

    try {
        const { resetToken, newPassword } = req.body;

        // Verify token and check if it's stored
        let decoded;
        try {
            decoded = jwt.verify(resetToken, JWT_SECRET);
            
            if (decoded.action !== 'password_reset') {
                throw new Error('Invalid token purpose');
            }

            if (!otpStore.resetTokens[resetToken] || 
                Date.now() > otpStore.resetTokens[resetToken].expiresAt) {
                throw new Error('Token not found or expired');
            }
        } catch (error) {
            logger.warn(`Invalid reset token attempt: ${error.message}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired reset token',
                code: 'INVALID_RESET_TOKEN'
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 12);

        // Update password and invalidate all sessions
        const result = await db.collection('registration').updateOne(
            { _id: new ObjectId(decoded.userId) },
            { 
                $set: { 
                    password: hashedPassword,
                    updatedAt: new Date() 
                } 
            }
        );

        if (result.modifiedCount === 0) {
            logger.error(`Password update failed for user: ${decoded.userId}`);
            return res.status(404).json({
                success: false,
                message: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        // Clean up reset token
        delete otpStore.resetTokens[resetToken];

        logger.info(`Password reset successful for user: ${decoded.userId}`);

        res.status(200).json({
            success: true,
            message: 'Password reset successfully'
        });

    } catch (error) {
        logger.error(`Password reset error: ${error.message}`, { stack: error.stack });
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
});

// Location sharing endpoint
app.post('/Explore/IamActive', authenticate, [
    body('uid').isString().notEmpty(),
    body('latitude').isFloat({ min: -90, max: 90 }),
    body('longitude').isFloat({ min: -180, max: 180 }),
    body('pincode').isString().isLength({ min: 5, max: 10 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false,
            errors: errors.array() 
        });
    }

    try {
        const { uid, latitude, longitude, pincode } = req.body;
        const userId = req.user._id;

        // Verify UID matches authenticated user
        const user = await db.collection('registration').findOne({
            _id: new ObjectId(userId),
            uid: uid
        });

        if (!user) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized UID'
            });
        }

        // Upsert location data
        const result = await db.collection('Active_Users').updateOne(
            { uid: uid },
            {
                $set: {
                    userId: new ObjectId(userId),
                    latitude: latitude,
                    longitude: longitude,
                    pincode: pincode,
                    timestamp: new Date(),
                    isActive: true
                }
            },
            { upsert: true }
        );

        // Log the activity
        await db.collection('activity_logs').insertOne({
            userId: new ObjectId(userId),
            action: 'activated',
            timestamp: new Date(),
            location: {
                latitude: latitude,
                longitude: longitude,
                pincode: pincode
            }
        });

        res.status(200).json({
            success: true,
            message: 'Location shared successfully'
        });

    } catch (error) {
        logger.error('Error saving location:', error);
        res.status(500).json({ 
            success: false,
            message: 'Failed to share location'
        });
    }
});

// Location deletion endpoint
app.delete('/Explore/IamActive', authenticate, async (req, res) => {
    try {
        const { uid } = req.query;
        const userId = req.user._id;

        // Verify UID matches authenticated user
        const user = await db.collection('registration').findOne({
            _id: new ObjectId(userId),
            uid: uid
        });

        if (!user) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized UID'
            });
        }

        // Get location before deleting for logging
        const location = await db.collection('Active_Users').findOne({ uid: uid });

        // Delete location data
        const result = await db.collection('Active_Users').deleteOne({ uid: uid });

        // Log the deactivation
        if (location) {
            await db.collection('activity_logs').insertOne({
                userId: new ObjectId(userId),
                action: 'deactivated',
                timestamp: new Date(),
                location: {
                    latitude: location.latitude,
                    longitude: location.longitude,
                    pincode: location.pincode
                }
            });
        }

        res.status(200).json({
            success: true,
            message: 'Location sharing stopped'
        });

    } catch (error) {
        logger.error('Error deleting location:', error);
        res.status(500).json({ 
            success: false,
            message: 'Failed to stop sharing location'
        });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    await connectDB();
    logger.info(`Server is running on port: ${PORT}`);
});
