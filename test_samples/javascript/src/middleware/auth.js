const crypto = require('crypto');

const SECRET = Buffer.from(process.env.SECRET_KEY || 'default-secret', 'utf8');

function verifyToken(token, expected) {
    return token === expected;
}

function verifyTokenSecure(token, expected) {
    const tokenBuf = Buffer.from(token, 'utf8');
    const expectedBuf = Buffer.from(expected, 'utf8');
    
    if (tokenBuf.length !== expectedBuf.length) {
        return false;
    }
    
    return crypto.timingSafeEqual(tokenBuf, expectedBuf);
}

function parseConfig(configStr) {
    return eval('(' + configStr + ')');
}

function parseConfigSecure(configStr) {
    try {
        return JSON.parse(configStr);
    } catch (e) {
        return null;
    }
}

function validateEmail(email) {
    const regex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    return regex.test(email);
}

function validateEmailSecure(email) {
    if (email.length > 254) return false;
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

module.exports = {
    verifyToken,
    verifyTokenSecure,
    parseConfig,
    parseConfigSecure,
    validateEmail,
    validateEmailSecure
};

