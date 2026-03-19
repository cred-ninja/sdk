/**
 * Cred SDK — Error classes
 */

export class CredError extends Error {
  readonly code: string;
  readonly statusCode: number;

  constructor(message: string, code: string, statusCode: number) {
    super(message);
    this.name = 'CredError';
    this.code = code;
    this.statusCode = statusCode;
    // Restore prototype chain (required for extends Error in TS)
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ConsentRequiredError extends CredError {
  readonly consentUrl: string;

  constructor(message: string, consentUrl: string) {
    super(message, 'consent_required', 403);
    this.name = 'ConsentRequiredError';
    this.consentUrl = consentUrl;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
