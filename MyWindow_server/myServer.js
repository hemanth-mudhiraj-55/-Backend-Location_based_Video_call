const express = require('express');
const { MongoClient } = require('mongodb');
const nodemailer = require('nodemailer');  // For sending OTP via email

const app = express();
const url = 'mongodb://localhost:27017';
const dbName = 'myWindow';

// Middleware to parse JSON requests
app.use(express.json());

let db;
let otpStore = {};  // Temporary storage for OTPs

// Function to connect to MongoDB
async function connectDB() {
    try {
        const client = await MongoClient.connect(url, { useNewUrlParser: true, useUnifiedTopology: true });
        db = client.db(dbName);
        console.log("Connected to MongoDB");
    } catch (error) {
        console.error("Error while connecting to MongoDB:", error);
        process.exit(1); // Exit if MongoDB connection fails
    }
}

// Setup Nodemailer transporter to send OTP
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'hemanththarun1@gmail.com',
        pass: 'your-email-password'  // Use environment variables in production
    }
});

// POST route to confirm user details and send OTP
app.post('/Confirm', async (req, res) => {
    try {
        if (!db) {
            
            console.log("Database is not connect")
        }

        const { uid, email, mobile, name } = req.body; // Only need uid, email, and mobile for OTP
        const collection = db.collection('registration');
        
        const query = {
            $or: [
                { email: email },
                { mobile: mobile }
            ]
        };

        const query2={
            uid :uid
        };

        // Check if user already exists
        const existingUser = await collection.findOne(query);
        const existing_uid =await collection.findOne(query2);

        if(existing_uid){
            return res.status(401).send({ message: "UID already exists" });
        }
        else{
            if (existingUser) {
                return res.status(400).send({ message: "Either mobile or email is already registered" });
            }
            else{
                        // Generate OTP (6-digit random number)
                    const email_otp = Math.floor(100000 + Math.random() * 900000);
                    otpStore[email] = email_otp;  // Store OTP temporarily (use a more secure storage in production)
    
                    // Send OTP via email
                    const mailOptions = {
                        from: 'hemanththarun1@gmail.com',
                        to: email,
                        subject: 'OTP for Mail verification in MyWindow application',
                        text: `Dear ${name},
                            \n                ${email_otp} is the OTP to validate your e-mail id for MyWindow Application
                                                
                            \n                    NOTE :- This is system generated mail, please do not reply to it. 
                                                
                            \n                    Regards,
                            \n                    Helpdesk MyWindow.`
                    };
    
                    transporter.sendMail(mailOptions, (error, info) => {
                        if (error) {
                            console.log('Error sending OTP:', error);
                            return res.status(500).send({ message: "Error sending OTP" });
                        }
                        console.log('OTP sent:', info.response);
                        res.status(200).send({ message: "OTP has sent. Please verify." });
                    });
            }
        }
        

        

    } catch (error) {
        console.error("Error in /Confirm route:", error);
        res.status(500).send({ message: "Internal server error" });
    }
});


// POST route to submit user details (after OTP verification)
app.post('/submit', async (req, res) => {
    try {
        const { email, email_otp, uid, name, mobile, password, gender, profile_pic } = req.body;

        // First, verify the OTP
        if (otpStore[email] === parseInt(email_otp)) {
            delete otpStore[email];  // OTP used, delete it

            // Insert user data into the database
            const collection = db.collection('registration');
            const newUser = { uid, name, email, mobile, password, gender, profile_pic };
            await collection.insertOne(newUser);

            res.status(200).send({ message: "User registered successfully" });
        } else {
            res.status(400).send({ message: "Invalid OTP" });
        }
    } catch (error) {
        console.error("Error in /submit route:", error);
        res.status(500).send({ message: "Internal server error" });
    }
});

// Start the server and connect to MongoDB
const PORT = 3000;
app.listen(PORT, async () => {
    await connectDB();
    console.log(`Listening on port: ${PORT}`);
});
