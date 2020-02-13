var crypto = require("crypto");
//解密
function AESDecrypt(param, desKey) {
    var cipherChunks = [];
    var decipher = crypto.createDecipheriv('aes-128-ecb', desKey, '');
    decipher.setAutoPadding(true);
    cipherChunks.push(decipher.update(param, 'base64', 'utf8'));
    cipherChunks.push(decipher.final('utf8'));
    return cipherChunks.join('');
}
//加密
function AESEncrypt(param, desKey) {
    var cipherChunks = [];
    var cipher = crypto.createCipheriv('aes-128-ecb', desKey, '');
    cipher.setAutoPadding(true);
    cipherChunks.push(cipher.update(param, 'utf8', 'base64'));
    cipherChunks.push(cipher.final('base64'));

    return cipherChunks.join('');
}
module.exports.AESDecrypt = AESDecrypt;//解密
module.exports.AESEncrypt = AESEncrypt;//加密