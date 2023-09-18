class BaseError<T extends string> extends Error {
  code: T;
  cause: any; /* eslint-disable-line @typescript-eslint/no-explicit-any */

  constructor({
    code,
    message,
    cause,
  }: {
    code: T;
    message: string;
    cause?: any /* eslint-disable-line @typescript-eslint/no-explicit-any */;
  }) {
    super(message);
    this.code = code;
    this.cause = cause;
    this.name = this.constructor.name;
  }
}

type VerificationErrorCode =
  | 'NOT_IMPLEMENTED_ERROR'
  | 'TLOG_INCLUSION_PROOF_ERROR'
  | 'TLOG_INCLUSION_PROMISE_ERROR'
  | 'TLOG_MISSING_INCLUSION_ERROR'
  | 'TLOG_BODY_ERROR'
  | 'CERTIFICATE_ERROR'
  | 'PUBLIC_KEY_ERROR'
  | 'SIGNATURE_ERROR'
  | 'TIMESTAMP_ERROR';

export class VerificationError extends BaseError<VerificationErrorCode> {
  // Using during transition to new error class. Callers should specify their own code
  constructor({
    code,
    message,
    cause,
  }: {
    code: VerificationErrorCode;
    message: string;
    cause?: any /* eslint-disable-line @typescript-eslint/no-explicit-any */;
  }) {
    super({ code, message, cause });
  }
}
