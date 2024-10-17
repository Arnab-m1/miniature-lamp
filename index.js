const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const path = require('path');
const { spawn } = require('child_process');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const { User, ApiKey } = require('./models');
const authMiddleware = require('./middleware/auth');
const { generateApiKey } = require('./utils');
require('dotenv').config()
const app = express();
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));


mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 5 * 60 * 1000 } // 5 minutes
}));

// Middleware to check for inactive sessions and logout
app.use((req, res, next) => {
    if (req.session) {
        if (Date.now() > req.session.cookie.expires) {
            req.session.destroy();
            res.redirect('/signin');
        } else {
            req.session.cookie.expires = Date.now() + 5 * 60 * 1000; // Reset expiration
            next();
        }
    } else {
        next();
    }
});

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.get('/signin', (req, res) => {
    res.render('signin');
});

app.get('/verify-otp', (req, res) => {
    res.render('verify-otp');
});

app.get('/key-management', (req, res) => {
    res.render('key-management');
});

app.get('/forget-password', (req, res) => {
    res.render('forget-password');
});

app.get('/reset-password', (req, res) => {
    res.render('reset-password');
});

// Function to generate JWT token
const generateAuthToken = (user) => {
    return jwt.sign({ _id: user._id.toString() }, process.env.SECRET_KEY, { expiresIn: '1h' });
};

// Function to start the subprocess for sending OTP email
const startSendOtpSubprocess = (email, otp) => {
    const subprocess = spawn('node', ['send-otp.js', email, otp]);

    subprocess.on('close', (code) => {
        if (code !== 0) {
            console.error(`Subprocess for sending OTP failed with code ${code}`);
        }
    });
};

// Signup
app.post('/signup', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Signup request received with email:', email);
        if (!email || !password) {
            return res.status(400).send({ error: 'Email and password are required.' });
        }

        const otpSecret = speakeasy.generateSecret().base32;
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const user = new User({ email, password: hashedPassword, otpSecret, verified: false });
        await user.save();

        const otp = speakeasy.totp({ secret: otpSecret, encoding: 'base32' });
        console.log(`Generated OTP for signup: ${otp}`);
        startSendOtpSubprocess(email, otp); // Start subprocess to send OTP
        req.session.email = email; // Store email in session
        console.log('User created and session set for email:', email);
        res.redirect('/verify-otp');
    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Signin
app.post('/signin', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Signin request received for email:', email);
        const user = await User.findOne({ email });
        if (!user || !user.verified) {
            return res.status(400).send({ error: 'User not found or not verified.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send({ error: 'Invalid credentials.' });
        }
        const otp = speakeasy.totp({ secret: user.otpSecret, encoding: 'base32' });
        console.log(`Generated OTP for signin: ${otp}`);
        startSendOtpSubprocess(email, otp); // Start subprocess to send OTP
        req.session.email = email; // Store email in session
        console.log('Signin successful and session set for email:', email);
        res.redirect('/verify-otp');
    } catch (error) {
        console.error('Error during signin:', error);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Forget Password
app.post('/forget-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send({ error: 'User not found.' });
        }
        const otp = speakeasy.totp({ secret: user.otpSecret, encoding: 'base32' });
        console.log(`Generated OTP for forget password: ${otp}`);
        startSendOtpSubprocess(email, otp); // Start subprocess to send OTP
        req.session.email = email; // Store email in session
        res.redirect('/reset-password');
    } catch (error) {
        console.error('Error during forget password:', error);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Verify OTP
app.post('/verify-otp', async (req, res) => {
    try {
        const { otp } = req.body;
        const email = req.session.email;
        console.log('Verify OTP request received for email:', email);
        if (!email) {
            return res.status(400).send({ error: 'Session expired or invalid request.' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send({ error: 'User not found.' });
        }

        const isVerified = speakeasy.totp.verify({ secret: user.otpSecret, encoding: 'base32', token: otp, window: 1 });
        if (isVerified) {
            user.verified = true;
            await user.save();
            const token = generateAuthToken(user);
            console.log('OTP verified and JWT token generated:', token);
            res.send({ token }); // Send the token back to the client
        } else {
            console.error('Invalid OTP:', otp);
            res.status(400).send({ error: 'Invalid OTP.' });
        }
    } catch (error) {
        console.error('Error during verify-otp:', error);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});


// Verify OTP and Reset Password
app.post('/reset-password', async (req, res) => {
    try {
        const { otp, newPassword } = req.body;
        const email = req.session.email;
        console.log('Reset password request received for email:', email);
        if (!email) {
            return res.status(400).send({ error: 'Session expired or invalid request.' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send({ error: 'User not found.' });
        }

        const isVerified = speakeasy.totp.verify({ secret: user.otpSecret, encoding: 'base32', token: otp, window: 1 });
        if (isVerified) {
            const saltRounds = 10;
            user.password = await bcrypt.hash(newPassword, saltRounds);
            await user.save();
            console.log('Password reset successful for email:', email);
            res.redirect('/signin');
        } else {
            console.error('Invalid OTP for password reset:', otp);
            res.status(400).send({ error: 'Invalid OTP.' });
        }
    } catch (error) {
        console.error('Error during reset password:', error);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Generate API Key
app.post('/api-keys', authMiddleware, async (req, res) => {
    try {
        const { name } = req.body;
        const apiKeysCount = await ApiKey.countDocuments({ userId: req.user._id });
        if (apiKeysCount >= 10) {
            const oldestApiKey = await ApiKey.findOne({ userId: req.user._id }).sort({ createdAt: 1 });
            await oldestApiKey.deleteOne();
        }
        const newApiKey = generateApiKey();
        const apiKey = new ApiKey({ key: newApiKey, name: name || 'Default Name', userId: req.user._id });
        await apiKey.save();
        res.send({ apiKey: apiKey });
    } catch (error) {
        console.error('Error during generate API key:', error);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// List API Keys
app.get('/api-keys', authMiddleware, async (req, res) => {
    try {
        const apiKeys = await ApiKey.find({ userId: req.user._id });
        res.send(apiKeys);
    } catch (error) {
        console.error('Error during list API keys:', error);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Delete API Key
app.delete('/api-keys/:id', authMiddleware, async (req, res) => {
    try {
        const apiKey = await ApiKey.findOne({ _id: req.params.id, userId: req.user._id });
        if (!apiKey) {
            return res.status(404).send({ error: 'API Key not found.' });
        }
        await apiKey.deleteOne();
        res.send({ message: 'API Key deleted.' });
    } catch (error) {
        console.error('Error during delete API key:', error);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Regenerate API Key
app.post('/api-keys/:id/regenerate', authMiddleware, async (req, res) => {
    try {
        const apiKey = await ApiKey.findOne({ _id: req.params.id, userId: req.user._id });
        if (!apiKey) {
            return res.status(404).send({ error: 'API Key not found.' });
        }
        apiKey.key = generateApiKey();
        await apiKey.save();
        res.send({ apiKey: apiKey });
    } catch (error) {
        console.error('Error during regenerate API key:', error);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/signin');
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

module.exports = app;
