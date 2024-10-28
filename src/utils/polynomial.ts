import bigInt from 'big-integer';
import { BigInteger } from './commonUtils';
import { PrimeGroup } from '../group';

export class ExponentPolynomial {
	private coefficients: BigInteger[];
	private group: PrimeGroup;

	constructor(coefficients: BigInteger[], group: PrimeGroup) {
		this.coefficients = coefficients;
		this.group = group;
	}

	public static randomPolynomial(
		constant: BigInteger | number,
		degree: number,
		group: PrimeGroup,
	): ExponentPolynomial {
		if (typeof constant === 'number') {
			constant = bigInt(constant);
		}
		const coefficients = new Array<BigInteger>(degree + 1);
		coefficients[0] = constant;
		for (let i = 1; i <= degree; i++) {
			coefficients[i] = group.randomExponent();
		}
		return new this(coefficients, group);
	}

	public evaluate(at: BigInteger | number): BigInteger {
		if (typeof at === 'number') {
			at = bigInt(at);
		}
		let result = this.coefficients[0];
		for (let i = 1; i < this.coefficients.length; i++) {
			result = result
				.times(at)
				.add(this.coefficients[i])
				.mod(this.group.getOrder());
		}
		return result;
	}
}
