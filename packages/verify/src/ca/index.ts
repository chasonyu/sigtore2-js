import { VerificationError } from '../error';
import { CertAuthority, TLogAuthority, filterCertAuthorities } from '../trust';
import { x509Certificate } from '../x509/cert';
import { verifyCertificateChain } from './chain';
import { verifySCTs } from './sct';

import type { SCTVerificationResult } from '../shared.types';

export type CertificateVerifierOptions = {
  certificateAuthorities: CertAuthority[];
  ctlogAuthorities: TLogAuthority[];
};

export class CertificateVerifier {
  private certificateAuthorities: CertAuthority[];
  private ctlogAuthorities: TLogAuthority[];

  constructor(options: CertificateVerifierOptions) {
    this.certificateAuthorities = options.certificateAuthorities;
    this.ctlogAuthorities = options.ctlogAuthorities;
  }

  public verify(
    leaf: x509Certificate,
    timestamp: Date
  ): SCTVerificationResult[] {
    const path = this.verifyLeafCertificate(leaf, timestamp);
    return verifySCTs(path[0], path[1], this.ctlogAuthorities);
  }

  // TODO: For consistency, should verifyCertificateChain accept a CertAuthority[]?
  private verifyLeafCertificate(
    leaf: x509Certificate,
    timestamp: Date
  ): x509Certificate[] {
    // Filter list of trusted CAs to those which are valid for the given
    // leaf certificate.
    const cas = filterCertAuthorities(this.certificateAuthorities, {
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
}
