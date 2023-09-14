import { verifyCertificateChain } from '../ca/chain';
import { verifySCTs } from '../ca/sct';
import { VerificationError } from '../error';
import { filterCertAuthorities } from '../trust';
import { crypto } from '../util';
import { x509Certificate } from '../x509/cert';

import type { KeyObject } from 'crypto';
import type {
  CertAuthority,
  KeyProvider,
  SCTVerificationResult,
  SignatureVerifier,
  TrustMaterial,
} from '../shared.types';

const OID_FULCIO_ISSUER = '1.3.6.1.4.1.57264.1.1';

export type VerifyKeyOptions = {
  provider: KeyProvider;
  trustMaterial: TrustMaterial;
  timestamp: Date;
};

export function verifyKey({
  provider,
  trustMaterial,
  timestamp,
}: VerifyKeyOptions): SignatureVerifier {
  const key = provider.key();

  switch (key.$case) {
    case 'public-key': {
      return extractPublicKeyVerifier(key.hint, timestamp, trustMaterial);
    }
    case 'certificate': {
      return extractCertificateVerifier(
        key.certificate,
        timestamp,
        trustMaterial
      );
    }
  }
}

function extractPublicKeyVerifier(
  hint: string,
  timestamp: Date,
  trustMaterial: TrustMaterial
): SignatureVerifier {
  const publicKey = verifyPublicKey(hint, timestamp, trustMaterial);

  return {
    scts: [],
    issuer: undefined,
    subject: undefined,
    verifySignature: (signature, data) =>
      crypto.verify(data, publicKey, signature),
  };
}

function extractCertificateVerifier(
  cert: x509Certificate,
  timestamp: Date,
  trustMaterial: TrustMaterial
): SignatureVerifier {
  const scts = verifyCertificate(cert, timestamp, trustMaterial);
  const publicKey = crypto.createPublicKey(cert.publicKey);
  return {
    scts,
    issuer: cert.extension(OID_FULCIO_ISSUER)?.value.toString('ascii'),
    subject: undefined,
    verifySignature: (signature, data) =>
      crypto.verify(data, publicKey, signature),
  };
}

function verifyPublicKey(
  hint: string,
  timestamp: Date,
  trustMaterial: TrustMaterial
): KeyObject {
  const key = trustMaterial.publicKey(hint);

  if (!key.validFor(timestamp)) {
    throw new VerificationError({
      code: 'PUBLIC_KEY_ERROR',
      message: 'Public key is not valid for the given timestamp',
    });
  }
  return key.publicKey;
}

function verifyCertificate(
  leaf: x509Certificate,
  timestamp: Date,
  trustMaterial: TrustMaterial
): SCTVerificationResult[] {
  const path = verifyLeafCertificate(
    leaf,
    timestamp,
    trustMaterial.certificateAuthorities
  );
  return verifySCTs(path[0], path[1], trustMaterial.ctlogs);
}

// TODO: For consistency, should verifyCertificateChain accept a CertAuthority[]?
function verifyLeafCertificate(
  leaf: x509Certificate,
  timestamp: Date,
  certificateAuthorities: CertAuthority[]
): x509Certificate[] {
  // Filter list of trusted CAs to those which are valid for the given
  // leaf certificate.
  const cas = filterCertAuthorities(certificateAuthorities, {
    start: leaf.notBefore,
    end: leaf.notAfter,
  });

  // Attempt to verify the certificate chain for each of the trusted CAs.
  // At least one of the trusted CAs must be able to verify the certificate
  // chain.
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  let error: any;
  for (const ca of cas) {
    try {
      const path = verifyCertificateChain({
        trustedCerts: ca.certChain,
        untrustedCert: leaf,
        validAt: timestamp,
      });

      // Exit as soon as we have a successful verification
      return path;
    } catch (err) {
      error = err;
    }
  }

  // If we failed to verify the certificate chain for all of the trusted
  // CAs, throw the last error we encountered.
  throw new VerificationError({
    code: 'CERTIFICATE_ERROR',
    message: 'Failed to verify certificate chain',
    cause: error,
  });
}
