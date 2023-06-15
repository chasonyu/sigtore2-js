import type { Bundle } from '@sigstore/bundle';
import type { Verifier } from '../verifier';

class SignatureVerifier implements Verifier {
  async verify(bundle: Bundle): Promise<void> {
    bundle;
  }
}
