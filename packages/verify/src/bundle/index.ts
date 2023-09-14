import {
  Bundle,
  TransparencyLogEntry,
  isBundleWithCertificateChain,
  isBundleWithPublicKey,
} from '@sigstore/bundle';
import type {
  KeyProvider,
  SignatureContent,
  SignatureProvider,
  TLogEntryProvider,
  TimestampProvider,
} from '../shared.types';
import { x509Certificate } from '../x509/cert';
import { DSSESignatureContent } from './dsse';
import { MessageSignatureContent } from './message';

export function signatureContent(bundle: Bundle): SignatureContent {
  switch (bundle.content.$case) {
    case 'dsseEnvelope':
      return new DSSESignatureContent(bundle.content.dsseEnvelope);
    case 'messageSignature':
      return new MessageSignatureContent(bundle.content.messageSignature);
  }
}

// TODO: Rename this
export function bundleWrapper(
  bundle: Bundle
): SignatureProvider & TLogEntryProvider & TimestampProvider & KeyProvider {
  return {
    signature: () => signatureContent(bundle),
    tlogEntries: () => bundle.verificationMaterial.tlogEntries,
    timestamps: () =>
      bundle.verificationMaterial.tlogEntries.map(
        (entry: TransparencyLogEntry) => ({
          $case: 'transparency-log',
          tlogEntry: entry,
        })
      ),
    key: () => {
      if (isBundleWithCertificateChain(bundle)) {
        return {
          $case: 'certificate',
          certificate: x509Certificate.parse(
            bundle.verificationMaterial.content.x509CertificateChain
              .certificates[0].rawBytes
          ),
        };
      } else if (isBundleWithPublicKey(bundle)) {
        return {
          $case: 'public-key',
          hint: bundle.verificationMaterial.content.publicKey.hint,
        };
      }

      throw 'oops';
    },
  };
}
