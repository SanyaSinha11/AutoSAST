const crypto = require('crypto');

const ALGORITHM = 'aes-256-cbc';
const STATIC_IV = Buffer.alloc(16, 0);

class TokenService {
    constructor(key) {
        this.key = Buffer.from(key, 'hex');
    }

    encrypt(data) {
        const cipher = crypto.createCipheriv(ALGORITHM, this.key, STATIC_IV);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    }

    encryptSecure(data) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(ALGORITHM, this.key, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    }
}

function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

function hashPasswordSecure(password) {
    const salt = crypto.randomBytes(16);
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
    return salt.toString('hex') + ':' + hash.toString('hex');
}

function generateToken() {
    return Math.random().toString(36).substring(2);
}

function generateTokenSecure() {
    return crypto.randomBytes(32).toString('hex');
}

module.exports = {
    TokenService,
    hashPassword,
    hashPasswordSecure,
    generateToken,
    generateTokenSecure
};

