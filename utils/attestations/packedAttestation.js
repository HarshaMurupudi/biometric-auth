const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const cose = require('cose');

const verifyPackedAttestation = (webAuthResponse) => {
  let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
  let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];
  let authDataStruct = parseAuthData(attestationStruct.authData);
  let clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
  let signatureBuffer = attestationStruct.attStmt.sig;
  let signatureBaseBuffer = Buffer.concat([attestationStruct.authData, clientDataHash]);

  if (attestationStruct.attStmt.x5c) {
    /* ----- Verify FULL attestation ----- */
    let leafCert = base64ToPem(attestationStruct.attStmt.x5c[0].toString('base64'));
    let certInfo = getCertificateInfo(leafCert);

    if (certInfo.subject.OU !== 'Authenticator Attestation')
      throw new Error('Batch certificate OU MUST be set strictly to "Authenticator Attestation"!');

    if (!certInfo.subject.CN)
      throw new Error('Batch certificate CN MUST no be empty!');

    if (!certInfo.subject.O)
      throw new Error('Batch certificate CN MUST no be empty!');

    if (!certInfo.subject.C || certInfo.subject.C.length !== 2)
      throw new Error('Batch certificate C MUST be set to two character ISO 3166 code!');

    if (certInfo.basicConstraintsCA)
      throw new Error('Batch certificate basic constraints CA MUST be false!');

    if (certInfo.version !== 3)
      throw new Error('Batch certificate version MUST be 3(ASN1 2)!');

    return crypto.createVerify('sha256')
      .update(signatureBaseBuffer)
      .verify(leafCert, signatureBuffer);
    /* ----- Verify FULL attestation ENDS ----- */
  } else if (attestationStruct.attStmt.ecdaaKeyId) {
    throw new Error('ECDAA IS NOT SUPPORTED YET!');
  } else {
    /* ----- Verify SURROGATE attestation ----- */
    return cose.verifySignature(signatureBuffer, signatureBaseBuffer, authDataStruct.cosePublicKeyBuffer);
    /* ----- Verify SURROGATE attestation ENDS ----- */
  }
}

module.exports = {
  verifyPackedAttestation
}