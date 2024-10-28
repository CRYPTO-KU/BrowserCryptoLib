import {
	BigInteger,
	randomBigInteger,
	randomMod,
	randomPrime,
} from './utils/commonUtils';

const MIN_MODULUS_LENGTH = 512;
const MIN_ORDER_LENGTH = 160;

export interface PrimeGroup {
	getModulus(): BigInteger;
	getOrder(): BigInteger;
	getGenerator(): BigInteger;
	randomElement(): BigInteger;
	randomExponent(): BigInteger;
}

export function genRandomGroup(
	modLen: number,
	ordLen: number,
	stat: number,
): PrimeGroup {
	return new RandomPrimeGroup(modLen, ordLen, stat);
}

class RandomPrimeGroup implements PrimeGroup {
	private readonly modulus: BigInteger;
	private readonly order: BigInteger;
	private readonly generator: BigInteger;

	constructor(modLen: number, ordLen: number, stat: number) {
		// Initial safety checks
		if (modLen < MIN_MODULUS_LENGTH) {
			throw Error('Group modulus too small.');
		}
		if (ordLen < MIN_ORDER_LENGTH) {
			throw Error('Group order too small.');
		}
		if (ordLen < stat * 2) {
			throw Error('Group order too small compared to stat.');
		}
		// Find a prime order
		this.order = randomPrime(ordLen, stat);
		// Find a prime modulus
		const factorLen = modLen - ordLen;
		let factor, modulus: BigInteger, BigInteger;
		do {
			factor = randomBigInteger(factorLen, true);
			modulus = this.order.times(factor).add(1);
		} while (
			modulus.bitLength().neq(modLen) ||
			!modulus.isProbablePrime(stat)
		);
		this.modulus = modulus;
		// Find a generator
		do {
			const gammaPrime = randomMod(this.modulus);
			this.generator = gammaPrime.modPow(factor, this.modulus);
		} while (this.generator.eq(1));
	}
	public getModulus(): BigInteger {
		return this.modulus;
	}
	public getOrder(): BigInteger {
		return this.order;
	}
	public getGenerator(): BigInteger {
		return this.generator;
	}

	public randomElement(): BigInteger {
		return this.generator.modPow(this.randomExponent(), this.modulus);
	}
	public randomExponent(): BigInteger {
		return randomMod(this.order);
	}
}
