import type { Bundle } from '@sigstore/bundle';
import type { TLogAuthority } from '../trust';
import type { Verifier } from '../verifier';

export type TransparencyLogVerifierOptions = {
  tlogAuthorities: TLogAuthority[];
  online: boolean;
};

export class TransparencyLogVerifier implements Verifier {
  private tlogAuthorities: TLogAuthority[];
  private online: boolean;

  constructor(options: TransparencyLogVerifierOptions) {
    this.tlogAuthorities = options.tlogAuthorities;
    this.online = options.online;
  }

  async verify(bundle: Bundle): Promise<void> {
    bundle;
  }
}
