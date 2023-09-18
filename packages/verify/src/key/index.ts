import { VerificationError } from '../error';
import { x509Certificate } from '../x509/cert';
import { verifyCertificateChain } from './chain';
import { VerifiedSCTProvider, verifySCTs } from './sct';

import type { KeyObject } from 'crypto';
import type { TrustMaterial } from '../trust';

export function verifyPublicKey(
  hint: string,
  timestamps: Date[],
  trustMaterial: TrustMaterial
): KeyObject {
  const key = trustMaterial.publicKey(hint);

  timestamps.forEach((timestamp) => {
    if (!key.validFor(timestamp)) {
      throw new VerificationError({
        code: 'PUBLIC_KEY_ERROR',
        message: `Public key is not valid for timestamp: ${timestamp.toISOString()}`,
      });
    }
  });

  return key.publicKey;
}

export function verifyCertificate(
  leaf: x509Certificate,
  timestamps: Date[],
  trustMaterial: TrustMaterial
): VerifiedSCTProvider[] {
  // Check that leaf certificate chains to a trusted CA
  const path = verifyCertificateChain(
    leaf,
    trustMaterial.certificateAuthorities
  );

  // Check that ALL certificates are valid for ALL of the timestamps
  const validForDate = timestamps.every((timestamp) =>
    path.every((cert) => cert.validForDate(timestamp))
  );

  if (!validForDate) {
    throw new VerificationError({
      code: 'CERTIFICATE_ERROR',
      message: 'certificate is not valid or expired at the specified date',
    });
  }

  return verifySCTs(path[0], path[1], trustMaterial.ctlogs);
}
