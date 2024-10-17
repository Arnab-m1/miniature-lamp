const nodemailer = require('nodemailer');
require('dotenv').config()

// Function to send OTP email
const sendOtpEmail = async (email, otp) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER, // Your email address
            pass: process.env.EMAIL_PASS // Your app password
        }
    });

    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your OTP Code',
            text: `Your OTP code is ${otp}`
        });
        console.log(`OTP ${otp} sent to ${email}`);
    } catch (err) {
        console.error('Error sending email:', err);
    }
};

// Parse arguments
const args = process.argv.slice(2);
const email = args[0];
const otp = args[1];

sendOtpEmail(email, otp).then(() => process.exit(0)).catch(() => process.exit(1));
