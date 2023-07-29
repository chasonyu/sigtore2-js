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
import { VerificationError } from '../error';

import type { TransparencyLogEntry } from '@sigstore/bundle';
import type {
  ProposedDSSEEntry,
  ProposedEntry,
  ProposedHashedRekordEntry,
  ProposedIntotoEntry,
} from '@sigstore/rekor-types';
import type { SignatureContent } from '../shared.types';

// Compare the given tlog entry to the given bundle
export function verifyTLogBody(
  entry: TransparencyLogEntry,
  sigContent: SignatureContent
): void {
  const { kind, version } = entry.kindVersion;
  const body: ProposedEntry = JSON.parse(
    entry.canonicalizedBody.toString('utf8')
  );

  if (kind !== body.kind || version !== body.apiVersion) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: `kind/version mismatch - expected: ${kind}/${version}, received: ${body.kind}/${body.apiVersion}`,
    });
  }

  switch (body.kind) {
    case 'dsse':
      return verifyDSSETLogBody(body, sigContent);
    case 'intoto':
      return verifyIntotoTLogBody(body, sigContent);
    case 'hashedrekord':
      return verifyHashedRekordTLogBody(body, sigContent);
    /* istanbul ignore next */
    default:
      throw new VerificationError({
        code: 'TLOG_BODY_ERROR',
        message: `unsupported kind: ${kind}`,
      });
  }
}

// Compare the given intoto tlog entry to the given bundle
function verifyDSSETLogBody(
  tlogEntry: ProposedDSSEEntry,
  content: SignatureContent
): void {
  switch (tlogEntry.apiVersion) {
    case '0.0.1':
      return verifyDSSE001TLogBody(tlogEntry, content);
    /* istanbul ignore next */
    default:
      throw new VerificationError({
        code: 'TLOG_BODY_ERROR',
        message: `unsupported dsse version: ${tlogEntry.apiVersion}`,
      });
  }
}

// Compare the given intoto tlog entry to the given bundle
function verifyIntotoTLogBody(
  tlogEntry: ProposedIntotoEntry,
  content: SignatureContent
): void {
  switch (tlogEntry.apiVersion) {
    case '0.0.2':
      return verifyIntoto002TLogBody(tlogEntry, content);
    default:
      throw new VerificationError({
        code: 'TLOG_BODY_ERROR',
        message: `unsupported intoto version: ${tlogEntry.apiVersion}`,
      });
  }
}

// Compare the given hashedrekord tlog entry to the given bundle
function verifyHashedRekordTLogBody(
  tlogEntry: ProposedHashedRekordEntry,
  content: SignatureContent
): void {
  switch (tlogEntry.apiVersion) {
    case '0.0.1':
      return verifyHashedrekord001TLogBody(tlogEntry, content);
    /* istanbul ignore next */
    default:
      throw new VerificationError({
        code: 'TLOG_BODY_ERROR',
        message: `unsupported hashedrekord version: ${tlogEntry.apiVersion}`,
      });
  }
}

// Compare the given dsse v0.0.1 tlog entry to the given DSSE envelope.
function verifyDSSE001TLogBody(
  tlogEntry: Extract<ProposedDSSEEntry, { apiVersion: '0.0.1' }>,
  content: SignatureContent
): void {
  // Ensure the bundle's DSSE and the tlog entry contain the same number of signatures
  if (tlogEntry.spec.signatures?.length !== 1) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'signature count mismatch',
    });
  }

  const tlogSig = tlogEntry.spec.signatures[0].signature;

  // Ensure that the signature in the bundle's DSSE matches tlog entry
  if (!content.compareSignature(Buffer.from(tlogSig, 'base64')))
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'tlog entry signature mismatch',
    });

  // Ensure the digest of the bundle's DSSE payload matches the digest in the
  // tlog entry
  const tlogHash =
    tlogEntry.spec.payloadHash?.value || /* istanbul ignore next */ '';

  if (!content.compareDigest(Buffer.from(tlogHash, 'hex'))) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'DSSE payload hash mismatch',
    });
  }
}

// Compare the given intoto v0.0.2 tlog entry to the given DSSE envelope.
function verifyIntoto002TLogBody(
  tlogEntry: Extract<ProposedIntotoEntry, { apiVersion: '0.0.2' }>,
  content: SignatureContent
): void {
  // Ensure the bundle's DSSE and the tlog entry contain the same number of signatures
  if (tlogEntry.spec.content.envelope.signatures?.length !== 1) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'signature count mismatch',
    });
  }

  // Signature is double-base64-encoded in the tlog entry
  const tlogSig = base64Decode(
    tlogEntry.spec.content.envelope.signatures[0].sig
  );

  // Ensure that the signature in the bundle's DSSE matches tlog entry
  if (!content.compareSignature(Buffer.from(tlogSig, 'base64')))
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'tlog entry signature mismatch',
    });

  // Ensure the digest of the bundle's DSSE payload matches the digest in the
  // tlog entry
  const tlogHash =
    tlogEntry.spec.content.payloadHash?.value || /* istanbul ignore next */ '';

  if (!content.compareDigest(Buffer.from(tlogHash, 'hex'))) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'DSSE payload hash mismatch',
    });
  }
}

// Compare the given hashedrekord v0.0.1 tlog entry to the given message
// signature
function verifyHashedrekord001TLogBody(
  tlogEntry: Extract<ProposedHashedRekordEntry, { apiVersion: '0.0.1' }>,
  content: SignatureContent
): void {
  // Ensure that the bundles message signature matches the tlog entry
  const tlogSig =
    tlogEntry.spec.signature.content || /* istanbul ignore next */ '';

  if (!content.compareSignature(Buffer.from(tlogSig, 'base64'))) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'signature mismatch',
    });
  }

  // Ensure that the bundle's message digest matches the tlog entry
  const tlogDigest =
    tlogEntry.spec.data.hash?.value || /* istanbul ignore next */ '';

  if (!content.compareDigest(Buffer.from(tlogDigest, 'hex'))) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'digest mismatch',
    });
  }
}

function base64Decode(str: string): string {
  return Buffer.from(str, 'base64').toString('utf-8');
}
