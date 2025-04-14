const express = require('express');
const twilio = require('twilio');
const { MongoClient, ObjectId } = require('mongodb');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const tls = require('tls');
const https = require('https');
// Add express-validator imports
const { body, validationResult } = require('express-validator'); // <-- Added this line

dotenv.config();

const app = express();
const url = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const dbName = 'MyWindow';
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Twilio credentials
const accountSid = process.env.TWILIO_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = new twilio(accountSid, authToken);

app.use(express.json());

let db;
let otpStore = {
    email: {},
    mobile: {}
};

// Create a custom agent to ignore self-signed certificate errors
const customAgent = new https.Agent({
    rejectUnauthorized: false
});

// Connect to MongoDB
async function connectDB() {
    try {
        const client = await MongoClient.connect(url);
        db = client.db(dbName);
        console.log('Connected to MongoDB');
    } catch (error) {
        console.error('Error while connecting to MongoDB:', error);
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
        console.log(`Message sent: ${message.sid}`);
    } catch (error) {
        console.error(`Error sending message: ${error.message}`);
    }
};

// Updated transporter configuration to handle self-signed certificates
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false
    },
    secure: false, // true for 465, false for other ports
    requireTLS: true,
    connectionTimeout: 10000, // 10 seconds
    socketTimeout: 10000, // 10 seconds
    logger: true,
    debug: true
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

    return new Promise((resolve, reject) => {
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending OTP:', error);
                reject(error);
            } else {
                console.log('OTP sent:', info.response);
                resolve(info);
            }
        });
    });
};

// Authentication middleware
const authenticate = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: "Authorization token required" });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await db.collection('registration').findOne({ _id: new ObjectId(decoded.userId) });
        if (!user) {
            return res.status(401).json({ error: "User not found" });
        }
        req.user = user;
        next();
    } catch (error) {
        console.error('JWT verification error:', error);
        res.status(401).json({ error: "Invalid token" });
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
        console.log(emailOtpData.otp)
        console.log(email_otp)
        console.log(mobileOtpData.otp)
        console.log(mobile_otp)
    
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
        
            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);
        
            // Create user document
            const newUser = {
                uid,
                name,
                email: email.toLowerCase(),
                mobile,
                password: hashedPassword,
                gender: gender.toLowerCase(),
                profile_pic: profile_pic || null,
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date(),
                lastLogin: null
            };
        
            const insertResult = await usersCollection.insertOne(newUser);
        
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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    await connectDB();
    console.log(`Server is running on port: ${PORT}`);
});
