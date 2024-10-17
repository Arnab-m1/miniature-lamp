const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, unique: true },
    password: String,
    otpSecret: String,
    verified: Boolean
});

const apiKeySchema = new mongoose.Schema({
    key: String,
    name: { type: String, default: 'Default Name' },
    userId: mongoose.Schema.Types.ObjectId,
    createdAt: { type: Date, default: Date.now },
    lastUsed: { type: Date }
});

const User = mongoose.model('User', userSchema);
const ApiKey = mongoose.model('ApiKey', apiKeySchema);

module.exports = { User, ApiKey };