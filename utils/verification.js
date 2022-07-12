const crypto = require('crypto');

/**
 * Takes signature, data and PEM public key and tries to verify signature
 * @param  {Buffer} signature
 * @param  {Buffer} data
 * @param  {String} publicKey - PEM encoded public key
 * @return {Boolean}
 */
let verifySignature = (signature, data, publicKey) => {
  return crypto.createVerify('SHA256')
    .update(data)
    .verify(publicKey, signature);
}

module.exports = {
  verifySignature
}