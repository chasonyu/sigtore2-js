import { Bundle, TransparencyLogEntry } from '@sigstore/bundle';
import { x509Certificate } from '../x509/cert';
import { DSSESignatureContent } from './dsse';
import { MessageSignatureContent } from './message';

import type {
  SignatureContent,
  SignedEntity,
  VerificationKey,
} from '../shared.types';

export function toSignedEntity(
  bundle: Bundle,
  artifact?: Buffer
): SignedEntity {
  return {
    signature: signatureContent(bundle, artifact),
    key: key(bundle),
    tlogEntries: bundle.verificationMaterial.tlogEntries,
    timestamps: bundle.verificationMaterial.tlogEntries.map(
      (entry: TransparencyLogEntry) => ({
        $case: 'transparency-log',
        tlogEntry: entry,
      })
    ),
  };
}

export function signatureContent(
  bundle: Bundle,
  artifact?: Buffer
): SignatureContent {
  switch (bundle.content.$case) {
    case 'dsseEnvelope':
      return new DSSESignatureContent(bundle.content.dsseEnvelope);
    case 'messageSignature':
      return new MessageSignatureContent(
        bundle.content.messageSignature,
        artifact!
      );
  }
}

function key(bundle: Bundle): VerificationKey {
  switch (bundle.verificationMaterial.content.$case) {
    case 'publicKey':
      return {
        $case: 'public-key',
        hint: bundle.verificationMaterial.content.publicKey.hint,
      };
    case 'x509CertificateChain':
      return {
        $case: 'certificate',
        certificate: x509Certificate.parse(
          bundle.verificationMaterial.content.x509CertificateChain
            .certificates[0].rawBytes
        ),
      };
  }
}
