const base64url = require('base64url');

/**
 * Converts PublicKeyCredential into serialised JSON
 * @param  {Object} pubKeyCred
 * @return {Object}            - JSON encoded publicKeyCredential
 */
export var publicKeyCredentialToJSON = (pubKeyCred) => {
  if (pubKeyCred instanceof Array) {
    let arr = [];
    for (let i of pubKeyCred)
      arr.push(publicKeyCredentialToJSON(i));

    return arr
  }

  if (pubKeyCred instanceof ArrayBuffer) {
    return base64url.encode(pubKeyCred)
  }

  if (pubKeyCred instanceof Object) {
    let obj = {};

    for (let key in pubKeyCred) {
      obj[key] = publicKeyCredentialToJSON(pubKeyCred[key])
    }

    return obj
  }

  return pubKeyCred
}

/**
 * Generate secure random buffer
 * @param  {Number} len - Length of the buffer (default 32 bytes)
 * @return {Uint8Array} - random string
 */
export var generateRandomBuffer = (len) => {
  len = len || 32;

  let randomBuffer = new Uint8Array(len);
  window.crypto.getRandomValues(randomBuffer);

  return randomBuffer
}

/**
 * Decodes arrayBuffer required fields.
 */
export var preformatMakeCredReq = (makeCredReq) => {
  makeCredReq.challenge = base64url.toBuffer(makeCredReq.challenge);
  makeCredReq.user.id = Buffer.from(base64url.decode(makeCredReq.user.id));

  return makeCredReq
}

/**
 * Decodes arrayBuffer required fields.
 */
export var preformatGetAssertReq = (getAssert) => {
  getAssert.challenge = Buffer.from(base64url.decode(getAssert.challenge), 'base64');
  const rawId = localStorage.getItem('rawId');

  for (let allowCred of getAssert.allowCredentials) {
    // const cred = strToBin(base64url.decode(allowCred.id))
    // allowCred.id = Buffer.from(base64url.decode(allowCred.id), 'base64');
    allowCred.id = strToBin(rawId);
  }

  return getAssert
}

// another function to go from string to ByteArray, but we first encode the
// string as base64 - note the use of the atob() function
export var strToBin = (str) => {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// function to encode raw binary to string, which is subsequently
// encoded to base64 - note the use of the btoa() function
export var binToStr = (bin) => {
  return btoa(new Uint8Array(bin).reduce(
    (s, byte) => s + String.fromCharCode(byte), ''
  ));
};

export const isWebauthnAvailable = async () => {
  const webAuthnAvailability = {
    status: false,
    message: ''
  };
  const { PublicKeyCredential } = window;



  if (typeof (PublicKeyCredential) == "undefined") {
    webAuthnAvailability.status = false;
    webAuthnAvailability.message = 'No support';

    return webAuthnAvailability;
  }

  const isUserVerifyingPlatformAuthnAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();

  if (!isUserVerifyingPlatformAuthnAvailable) {
    webAuthnAvailability.status = false;
    webAuthnAvailability.message = "In-built biometric authenticator isn't available";

    return webAuthnAvailability;
  }

  webAuthnAvailability.status = true;
  return webAuthnAvailability;

}