const base64url = require('base64url');

function strToBin(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

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
  makeCredReq.challenge = Buffer.from(base64url.decode(makeCredReq.challenge), 'base64');
  makeCredReq.user.id = Buffer.from(base64url.decode(makeCredReq.user.id), 'base64');

  return makeCredReq
}

/**
 * Decodes arrayBuffer required fields.
 */
export var preformatGetAssertReq = (getAssert) => {
  getAssert.challenge = Buffer.from(base64url.decode(getAssert.challenge), 'base64');
  const rawId = localStorage.getItem('rawId');

  for (let allowCred of getAssert.allowCredentials) {
    // console.log(typeof base64url.decode(allowCred.id))
    // const cred = strToBin(base64url.decode(allowCred.id))
    // const cred = strToBin(base64url.decode(allowCred.id))
    // alert(cred)

    // allowCred.id = Buffer.from(base64url.decode(allowCred.id), 'base64');
    allowCred.id = strToBin(rawId);
  }

  return getAssert
}