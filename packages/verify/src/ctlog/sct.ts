/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { crypto } from '../util';
import { ByteStream } from '../util/stream';
import { EXTENSION_OID_SCT, x509Certificate } from '../x509/cert';
import { x509SCTExtension } from '../x509/ext';

import type { TransparencyLogInstance } from '../trust';
interface SCTVerificationResult {
  verified: boolean;
  logID: Buffer;
}

export function verifySCTs(
  cert: x509Certificate,
  issuer: x509Certificate,
  ctlogs: TransparencyLogInstance[]
): SCTVerificationResult[] {
  let extSCT: x509SCTExtension | undefined;

  // Verifying the SCT requires that we remove the SCT extension and
  // re-encode the TBS structure to DER -- this value is part of the data
  // over which the signature is calculated. Since this is a destructive action
  // we create a copy of the certificate so we can remove the SCT extension
  // without affecting the original certificate.
  const clone = cert.clone();

  // Intentionally not using the findExtension method here because we want to
  // remove the the SCT extension from the certificate before calculating the
  // PreCert structure
  for (let i = 0; i < clone.extensions.length; i++) {
    const ext = clone.extensions[i];

    if (ext.subs[0].toOID() === EXTENSION_OID_SCT) {
      extSCT = new x509SCTExtension(ext);

      // Remove the extension from the certificate
      clone.extensions.splice(i, 1);
      break;
    }
  }

  if (!extSCT) {
    throw new Error('Certificate does not contain SCT extension');
  }

  /* istanbul ignore if -- too difficult to fabricate test case for this */
  if (extSCT.signedCertificateTimestamps.length === 0) {
    throw new Error('Certificate does not contain any SCTs');
  }

  // Construct the PreCert structure
  // https://www.rfc-editor.org/rfc/rfc6962#section-3.2
  const preCert = new ByteStream();

  // Calculate hash of the issuer's public key
  const issuerId = crypto.hash(issuer.publicKey);
  preCert.appendView(issuerId);

  // Re-encodes the certificate to DER after removing the SCT extension
  const tbs = clone.tbsCertificate.toDER();
  preCert.appendUint24(tbs.length);
  preCert.appendView(tbs);

  // Calculate and return the verification results for each SCT
  return extSCT.signedCertificateTimestamps.map((sct) => {
    let verified = false;

    // Find the ctlog instance that corresponds to the SCT's logID
    const log = ctlogs.find((log) => log.logId.keyId.equals(sct.logID));

    if (log) {
      const key = crypto.createPublicKey(log.publicKey.rawBytes);
      verified = sct.verify(preCert.buffer, key);
    }

    return { logID: sct.logID, verified };
  });
}
