const crypto = require('crypto');

function generateApiKey() {
    return crypto.randomBytes(20).toString('hex');
}

module.exports = { generateApiKey };
