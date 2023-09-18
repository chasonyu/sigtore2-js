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
import { VerificationError } from '../../error';
import { verifyCertificateChain } from '../../key/chain';
import { x509Certificate } from '../../x509/cert';
import { certificates } from '../__fixtures__/certs';

import type { CertAuthority } from '../../trust';

describe('verifyCertificateChain', () => {
  const rootCert = x509Certificate.parse(certificates.root);
  const intCert = x509Certificate.parse(certificates.intermediate);
  const leafCert = x509Certificate.parse(certificates.leaf);
  const invalidLeafCert = x509Certificate.parse(certificates.invalidleaf);
  const invalidIntCert = x509Certificate.parse(certificates.invalidint);
  const deepLeafCert = x509Certificate.parse(certificates.deepleaf);

  describe('when there are no matching CAs', () => {
    const cas: CertAuthority[] = [
      {
        certChain: [leafCert],
        validFor: { start: new Date(0), end: new Date('2100-01-01') },
      },
    ];

    it('throws an error', () => {
      expect(() => verifyCertificateChain(rootCert, cas)).toThrowWithCode(
        VerificationError,
        'CERTIFICATE_ERROR'
      );
    });
  });

  describe('when no path contains a trusted cert', () => {
    const cas: CertAuthority[] = [];

    it('throws an error', () => {
      expect(() => verifyCertificateChain(rootCert, cas)).toThrowWithCode(
        VerificationError,
        'CERTIFICATE_ERROR'
      );
    });
  });

  describe('when the certificate issuer cannot be located', () => {
    const cas: CertAuthority[] = [];

    it('throws an error', () => {
      expect(() => verifyCertificateChain(leafCert, cas)).toThrowWithCode(
        VerificationError,
        'CERTIFICATE_ERROR'
      );
    });
  });

  describe('when a non-CA cert is used to sign the leaf', () => {
    const cas: CertAuthority[] = [
      {
        certChain: [rootCert, intCert, leafCert],
        validFor: { start: new Date(0), end: new Date('2100-01-01') },
      },
    ];

    it('throws an error', () => {
      expect(() =>
        verifyCertificateChain(invalidLeafCert, cas)
      ).toThrowWithCode(VerificationError, 'CERTIFICATE_ERROR');
    });
  });

  describe('when the pathlen constraint is violated', () => {
    const cas: CertAuthority[] = [
      {
        certChain: [rootCert, intCert, invalidIntCert],
        validFor: { start: new Date(0), end: new Date('2100-01-01') },
      },
    ];

    it('throws an error', () => {
      expect(() => verifyCertificateChain(deepLeafCert, cas)).toThrowWithCode(
        VerificationError,
        'CERTIFICATE_ERROR'
      );
    });
  });

  describe('when the cert chain is valid', () => {
    const cas: CertAuthority[] = [
      {
        certChain: [rootCert, intCert],
        validFor: { start: new Date(0), end: new Date('2100-01-01') },
      },
    ];

    it('does not throw an error', () => {
      expect(() => verifyCertificateChain(leafCert, cas)).not.toThrowError();
    });

    it('returns the trusted chain', () => {
      const trustedChain = verifyCertificateChain(leafCert, cas);
      expect(trustedChain).toBeDefined();
      expect(trustedChain).toHaveLength(3);

      // The first cert in the chain is the leaf cert
      expect(trustedChain[0]).toEqual(leafCert);
    });
  });

  describe('when the certificate chain contains a single valid cert', () => {
    const cas: CertAuthority[] = [
      {
        certChain: [rootCert],
        validFor: { start: new Date(0), end: new Date('2100-01-01') },
      },
    ];

    it('does not throw an error', () => {
      expect(() => verifyCertificateChain(rootCert, cas)).not.toThrowError();
    });

    it('returns the trusted chain', () => {
      const trustedChain = verifyCertificateChain(rootCert, cas);
      expect(trustedChain).toBeDefined();
      expect(trustedChain).toHaveLength(1);
      expect(trustedChain[0]).toEqual(rootCert);
    });
  });
});
