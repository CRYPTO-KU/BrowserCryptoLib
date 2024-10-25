type ErrorName = 'UNDEFINED_ENVIRONMENT_ERROR' | 'UNAVAILABLE_CRYPTO_ERROR';

export class UtilsError extends Error {
  public name: ErrorName;
  public message: string;
  public cause: any;

  constructor({
    name,
    message,
    cause,
  }: {
    name: ErrorName;
    message: string;
    cause?: any;
  }) {
    super();
    this.name = name;
    this.message = message;
    this.cause = cause;
  }
}