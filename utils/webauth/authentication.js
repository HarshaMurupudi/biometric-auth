const base64url = require('base64url');
const cose = require('cose');
const {
  hash,
  parseAuthData,
  findAuthr,
  randomBase64URLBuffer
} = require('../conversion');

/**
 * Generates getAssertion request
 * @param  {Array} authenticators              - list of registered authenticators
 * @return {PublicKeyCredentialRequestOptions} - server encoded get assertion request
 */
let generateServerGetAssertion = (authenticators) => {
  let allowCredentials = [];
  for (let authr of authenticators) {
    allowCredentials.push({
      type: 'public-key',
      id: authr.credId,
      // id: 'AevmaVOaghwaoGM5Pp4A6XMUTnMDGrLrYMYxJxyEb_lIdcI2S4Zx653EJV2SaKXtiTB4cjzXcpo-18Dtu6Zwy4Y',
      // transports: ['usb', 'nfc', 'ble']
      transports: ["internal"]
    })
  }
  return {
    challenge: randomBase64URLBuffer(32),
    allowCredentials: allowCredentials,
    userVerification: "required",
  }
}

let verifyAuthenticatorAssertionResponse = (webAuthnResponse, authenticators) => {
  let authr = findAuthr(webAuthnResponse.id, authenticators);
  let pubKeyBuffer = base64url.toBuffer(authr.cosePublicKey);
  let clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
  let authDataBuffer = base64url.toBuffer(webAuthnResponse.response.authenticatorData);
  let authDataStruct = parseAuthData(authDataBuffer);
  let signatureBuffer = base64url.toBuffer(webAuthnResponse.response.signature);
  let signatureBaseBuffer = Buffer.concat([authDataBuffer, clientDataHash]);

  let response = { 'verified': false };
  if (!authDataStruct.flags.up) {
    console.log('User was NOT presented durring authentication!');
    return response
  }

  response.verified = cose.verifySignature(signatureBuffer, signatureBaseBuffer, pubKeyBuffer)

  if (response.verified) {
    console.log(response);
    // if (authDataStruct.counter <= authr.counter)
    //   throw new Error('Authr counter did not increase!');

    // authr.counter = authDataStruct.counter
  }

  return response
}

module.exports = {
  generateServerGetAssertion,
  verifyAuthenticatorAssertionResponse
}