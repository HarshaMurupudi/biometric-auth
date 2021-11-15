const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const {
  hash,
  COSEECDHAtoPKCS,
  ASN1toPEM,
  parseAuthData,
  randomBase64URLBuffer
} = require('../conversion');
const { verifySignature } = require('../verification');
const { verifyAndroidAttestation } = require('../attestations/androidAttestation');
const { verifyAppleAnonymousAttestation } = require('../attestations/appleAttestation.js')
const { verifyPackedAttestation } = require('../attestations/packedAttestation');

/**
 * Generates makeCredentials request
 * @param  {String} username       - username
 * @param  {String} displayName    - user's personal display name
 * @param  {String} id             - user's base64url encoded id
 * @return {MakePublicKeyCredentialOptions} - server encoded make credentials request
 */
let generateServerMakeCredRequest = (username, displayName, id) => {
  return {
    challenge: randomBase64URLBuffer(32),
    rp: {
      name: "ACME Corporation"
    },
    user: {
      id: id,
      name: username,
      displayName: displayName
    },
    attestation: 'direct',
    pubKeyCredParams: [
      {
        type: "public-key", alg: -7 // "ES256" IANA COSE Algorithms registry
      }
    ]
  }
}

let verifyAuthenticatorAttestationResponse = (webAuthnResponse) => {
  const { rawId } = webAuthnResponse;
  let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
  let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];
  let authDataStruct = parseAuthData(attestationStruct.authData);
  let clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
  let signatureBuffer = attestationStruct.attStmt.sig;

  let response = { 'verified': false };
  if (attestationStruct.fmt === 'fido-u2f') {
    if (!authDataStruct.flags.up) {
      console.log('User was NOT presented durring authentication!');
      return response
    }
    let reservedByte = Buffer.from([0x00]);
    let publicKey = COSEECDHAtoPKCS(authDataStruct.cosePublicKeyBuffer);
    let signatureBase = Buffer.concat([reservedByte, authDataStruct.rpIdHash, clientDataHash, authDataStruct.credIdBuffer, publicKey]);
    let PEMCertificate = ASN1toPEM(attestationStruct.attStmt.x5c[0]);
    response.verified = verifySignature(signatureBuffer, signatureBase, PEMCertificate)
  } else if (attestationStruct.fmt === 'packed') {
    response.verified = verifyPackedAttestation(webAuthnResponse)
  } else if (attestationStruct.fmt === 'android-safetynet') {
    response.verified = verifyAndroidAttestation(webAuthnResponse)
  }
  else if (attestationStruct.fmt === "apple") {
    response.verified = verifyAppleAnonymousAttestation(webAuthnResponse)
  }
  else {
    throw new Error(`The attestation type "${attestationStruct.fmt}" is not currently supported!`)
  }

  if (response.verified) {
    response.authrInfo = {
      fmt: 'fido-u2f',
      cosePublicKey: base64url.encode(authDataStruct.cosePublicKeyBuffer),
      counter: authDataStruct.counter,
      credId: base64url.encode(rawId)
    }
  }

  return response
}

module.exports = {
  generateServerMakeCredRequest,
  verifyAuthenticatorAttestationResponse
}