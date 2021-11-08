const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const vanillacbor = require('vanillacbor');
var jsrsasign = require('jsrsasign');

/**
 * Returns SHA-256 digest of the given data.
 * @param  {Buffer} data - data to hash
 * @return {Buffer}      - the hash
 */
let hash = (data) => {
  return crypto.createHash('SHA256').update(data).digest();
}

var getCertificateSubject = (certificate) => {
  let subjectCert = new jsrsasign.X509();
  subjectCert.readCertPEM(certificate);

  let subjectString = subjectCert.getSubjectString();
  let subjectFields = subjectString.slice(1).split('/');

  let fields = {};
  for (let field of subjectFields) {
    let kv = field.split('=');
    fields[kv[0]] = kv[1];
  }

  return fields
}

var validateCertificatePath = (certificates) => {
  if ((new Set(certificates)).size !== certificates.length)
    throw new Error('Failed to validate certificates path! Dublicate certificates detected!');

  for (let i = 0; i < certificates.length; i++) {
    let subjectPem = certificates[i];
    let subjectCert = new jsrsasign.X509();
    subjectCert.readCertPEM(subjectPem);

    let issuerPem = '';
    if (i + 1 >= certificates.length)
      issuerPem = subjectPem;
    else
      issuerPem = certificates[i + 1];

    let issuerCert = new jsrsasign.X509();
    issuerCert.readCertPEM(issuerPem);

    console.log(subjectCert.getIssuerString(), issuerCert.getSubjectString())

    if (subjectCert.getIssuerString() !== issuerCert.getSubjectString())
      throw new Error('Failed to validate certificate path! Issuers dont match!');

    let subjectCertStruct = jsrsasign.ASN1HEX.getTLVbyList(subjectCert.hex, 0, [0]);
    let algorithm = subjectCert.getSignatureAlgorithmField();
    let signatureHex = subjectCert.getSignatureValueHex()

    let Signature = new jsrsasign.crypto.Signature({ alg: algorithm });
    Signature.init(issuerPem);
    Signature.updateHex(subjectCertStruct);

    if (!Signature.verify(signatureHex))
      throw new Error('Failed to validate certificate path!')
  }

  return true
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

const verifyAndroidAttestation = (webAuthResponse) => {
  const { rawId } = webAuthResponse;
  let attestationBuffer = base64url.toBuffer(webAuthResponse.response.attestationObject);
  let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];
  let authDataStruct = parseAuthData(attestationStruct.authData);
  let clientDataHash = hash(base64url.toBuffer(webAuthResponse.response.clientDataJSON))
  let signatureBuffer = attestationStruct.attStmt.sig;
  // let signatureBaseBuffer = Buffer.concat([attestationStruct.authData, clientDataHash]);

  console.log("hit android-safetynet")
  let gsr1 = 'MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxTaWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZjc6j40 + Kfvvxi4Mla + pIH / EqsLmVEQS98GPR4mdmzxzdzxtIK + 6NiY6arymAZavpxy0Sy6scTHAHoT0KMM0VjU / 43dSMUBUc71DuxC73 / OlS8pF94G3VNTCOXkNz8kHp1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm / k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdGsnUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT / LCrBbBlDSgeF59N89iFo7 + ryUp9 / k5DPAgMBAAGjQjBAMA4GA1UdDwEB / wQEAwIBBjAPBgNVHRMBAf8EBTADAQH / MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0BAQUFAAOCAQEA1nPnfE920I2 / 7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOzyj1hTdNGCbM + w6DjY1Ub8rrvrTnhQ7k4o + YviiY776BQVvnGCv04zcQLcFGUl5gE38NflNUVyRRBnMRddWQVDf9VMOyGj / 8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymPAbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr + WymXUadDKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU / Qr6cf9tveCX4XSQRjbgbMEHMUfpIBvFSDJ3gyICh3WZlXi / EjJKSZp4A =='
  let jwsString = attestationStruct.attStmt.response.toString('utf8');
  let jwsParts = jwsString.split('.');

  let HEADER = JSON.parse(base64url.decode(jwsParts[0]));
  let PAYLOAD = JSON.parse(base64url.decode(jwsParts[1]));
  let SIGNATURE = jwsParts[2];

  /* ----- Verify payload ----- */
  let nonceBase = Buffer.concat([attestationStruct.authData, clientDataHash]);
  let nonceBuffer = hash(nonceBase);
  let expectedNonce = nonceBuffer.toString('base64');

  if (PAYLOAD.nonce !== expectedNonce)
    throw new Error(`PAYLOAD.nonce does not contains expected nonce! Expected ${PAYLOAD.nonce} to equal ${expectedNonce}!`);

  if (!PAYLOAD.ctsProfileMatch)
    throw new Error('PAYLOAD.ctsProfileMatch is FALSE!');
  /* ----- Verify payload ENDS ----- */


  /* ----- Verify header ----- */
  let certPath = HEADER.x5c.concat([gsr1]).map((cert) => {
    let pemcert = '';
    for (let i = 0; i < cert.length; i += 64)
      pemcert += cert.slice(i, i + 64) + '\n';

    return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
  })

  if (getCertificateSubject(certPath[0]).CN !== 'attest.android.com')
    throw new Error('The common name is not set to "attest.android.com"!');

  validateCertificatePath(certPath);
  /* ----- Verify header ENDS ----- */

  /* ----- Verify signature ----- */
  let signatureBaseBuffer = Buffer.from(jwsParts[0] + '.' + jwsParts[1]);
  let certificate = certPath[0];
  signatureBuffer = base64url.toBuffer(SIGNATURE);

  return crypto.createVerify('sha256')
    .update(signatureBaseBuffer)
    .verify(certificate, signatureBuffer);
}


module.exports = {
  verifyAndroidAttestation
}
