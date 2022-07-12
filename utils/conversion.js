const cbor = require('cbor');
const crypto = require('crypto');
const vanillacbor = require('vanillacbor');
const base64url = require('base64url');

/**
 * Returns SHA-256 digest of the given data.
 * @param  {Buffer} data - data to hash
 * @return {Buffer}      - the hash
 */
let hash = (data) => {
  return crypto.createHash('SHA256').update(data).digest();
}

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
let COSEECDHAtoPKCS = (COSEPublicKey) => {
  /* 
     +------+-------+-------+---------+----------------------------------+
     | name | key   | label | type    | description                      |
     |      | type  |       |         |                                  |
     +------+-------+-------+---------+----------------------------------+
     | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
     |      |       |       | tstr    | the COSE Curves registry         |
     |      |       |       |         |                                  |
     | x    | 2     | -2    | bstr    | X Coordinate                     |
     |      |       |       |         |                                  |
     | y    | 2     | -3    | bstr /  | Y Coordinate                     |
     |      |       |       | bool    |                                  |
     |      |       |       |         |                                  |
     | d    | 2     | -4    | bstr    | Private key                      |
     +------+-------+-------+---------+----------------------------------+
  */

  let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
  let tag = Buffer.from([0x04]);
  let x = coseStruct.get(-2);
  let y = coseStruct.get(-3);

  return Buffer.concat([tag, x, y])
}

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
let ASN1toPEM = (pkBuffer) => {
  if (!Buffer.isBuffer(pkBuffer))
    throw new Error("ASN1toPEM: pkBuffer must be Buffer.")

  let type;
  if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
    /*
        If needed, we encode rawpublic key to ASN structure, adding metadata:
        SEQUENCE {
          SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
             OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
          }
          BITSTRING <raw public key>
        }
        Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
    */

    pkBuffer = Buffer.concat([
      new Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
      pkBuffer
    ]);

    type = 'PUBLIC KEY';
  } else {
    type = 'CERTIFICATE';
  }

  let b64cert = pkBuffer.toString('base64');

  let PEMKey = '';
  for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
    let start = 64 * i;

    PEMKey += b64cert.substr(start, 64) + '\n';
  }

  PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;

  return PEMKey
}

const parseAuthData = (buffer) => {
  if (buffer.byteLength < 37)
    throw new Error('Authenticator Data must be at least 37 bytes long!');

  let rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32);

  /* Flags */
  let flagsBuffer = buffer.slice(0, 1); buffer = buffer.slice(1);
  let flagsInt = flagsBuffer[0];
  let up = !!(flagsInt & 0x01); // Test of User Presence
  let uv = !!(flagsInt & 0x04); // User Verification
  let at = !!(flagsInt & 0x40); // Attestation data
  let ed = !!(flagsInt & 0x80); // Extension data
  let flags = { up, uv, at, ed, flagsInt };

  let counterBuffer = buffer.slice(0, 4); buffer = buffer.slice(4);
  let counter = counterBuffer.readUInt32BE(0);

  /* Attested credential data */
  let aaguid = undefined;
  let aaguidBuffer = undefined;
  let credIdBuffer = undefined;
  let cosePublicKeyBuffer = undefined;
  let attestationMinLen = 16 + 2 + 16 + 77; // aaguid + credIdLen + credId + pk


  if (at) { // Attested Data
    if (buffer.byteLength < attestationMinLen)
      throw new Error(`It seems as the Attestation Data flag is set, but the remaining data is smaller than ${attestationMinLen} bytes. You might have set AT flag for the assertion response.`)

    aaguid = buffer.slice(0, 16).toString('hex'); buffer = buffer.slice(16);
    aaguidBuffer = `${aaguid.slice(0, 8)}-${aaguid.slice(8, 12)}-${aaguid.slice(12, 16)}-${aaguid.slice(16, 20)}-${aaguid.slice(20)}`;

    let credIdLenBuffer = buffer.slice(0, 2); buffer = buffer.slice(2);
    let credIdLen = credIdLenBuffer.readUInt16BE(0);
    credIdBuffer = buffer.slice(0, credIdLen); buffer = buffer.slice(credIdLen);

    let pubKeyLength = vanillacbor.decodeOnlyFirst(buffer).byteLength;
    cosePublicKeyBuffer = buffer.slice(0, pubKeyLength); buffer = buffer.slice(pubKeyLength);
  }

  let coseExtensionsDataBuffer = undefined;
  if (ed) { // Extension Data
    let extensionsDataLength = vanillacbor.decodeOnlyFirst(buffer).byteLength;

    coseExtensionsDataBuffer = buffer.slice(0, extensionsDataLength); buffer = buffer.slice(extensionsDataLength);
  }

  if (buffer.byteLength)
    throw new Error('Failed to decode authData! Leftover bytes been detected!');

  return { rpIdHash, counter, flags, counterBuffer, aaguid, credIdBuffer, cosePublicKeyBuffer, coseExtensionsDataBuffer }
}

/**
 * Takes an array of registered authenticators and find one specified by credId
 * @param  {String} credId        - base64url encoded credential
 * @param  {Array} authenticators - list of authenticators
 * @return {Object}               - found authenticator
 */
let findAuthr = (credId, authenticators) => {
  for (let authr of authenticators) {
    // if (base64url.decode(authr.credId) === credId)
    if (authr.credId === credId)
      return authr
    // if (base64url.decode(authr.credId) === credId)
    //   return authr
  }

  throw new Error(`Unknown authenticator with credId ${credId}!`)
}


/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
let randomBase64URLBuffer = (len) => {
  len = len || 32;
  let buff = crypto.randomBytes(len);

  return base64url(buff);
}

module.exports = {
  hash,
  COSEECDHAtoPKCS,
  ASN1toPEM,
  parseAuthData,
  findAuthr,
  randomBase64URLBuffer
}