import type { Bundle } from '@sigstore/bundle';
import type {
  SignatureContent,
  SignatureProvider,
  TLogEntryProvider,
} from '../shared.types';
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
): SignatureProvider & TLogEntryProvider {
  return {
    signature: () => signatureContent(bundle),
    tlogEntries: () => bundle.verificationMaterial.tlogEntries,
  };
}
