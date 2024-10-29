type UtilsErrorName =
	| 'UNDEFINED_ENVIRONMENT_ERROR'
	| 'UNAVAILABLE_CRYPTO_ERROR';
type LogicErrorName = 'UNEXPECTED_PRECOMPUTATION';

export class UtilsError extends Error {
	public name: UtilsErrorName;
	public message: string;
	public cause: any;

	constructor({
		name,
		message,
		cause,
	}: {
		name: UtilsErrorName;
		message: string;
		cause?: any;
	}) {
		super();
		this.name = name;
		this.message = message;
		this.cause = cause;
	}
}

export class LogicError extends Error {
	public name: LogicErrorName;
	public message: string;
	public cause: any;

	constructor({
		name,
		message,
		cause,
	}: {
		name: LogicErrorName;
		message: string;
		cause?: any;
	}) {
		super();
		this.name = name;
		this.message = message;
		this.cause = cause;
	}
}
