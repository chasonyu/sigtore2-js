import type { Bundle } from '@sigstore/bundle';
import type { TransparencyLogInstance } from '../trust';
import type { Verifier } from '../verifier';

export type TransparencyLogVerifierOptions = {
  tlogInstances: TransparencyLogInstance[];
  online: boolean;
};

export class TransparencyLogVerifier implements Verifier {
  private tlogInstances: TransparencyLogInstance[];
  private online: boolean;

  constructor(options: TransparencyLogVerifierOptions) {
    this.tlogInstances = options.tlogInstances;
    this.online = options.online;
  }

  async verify(bundle: Bundle): Promise<void> {
    bundle;
  }
}
