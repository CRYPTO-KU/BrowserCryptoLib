import bigInt from 'big-integer';
import { PrimeGroup } from '../group';
import { BigInteger } from './commonUtils';
import { ExponentPolynomial } from './polynomial';

export class Share {
	constructor(
		public index: number,
		public value: BigInteger,
		public lambda?: BigInteger,
	) {}

	calculateLambda(availableShareCount: number, modulus: BigInteger) {
		let lambda = bigInt(1);
		for (let j = 1; j < availableShareCount; j++) {
			if (j == this.index) {
				continue;
			}
			const inv = bigInt(j - this.index).modInv(modulus); // 1 / (j - i)
			const factor = inv.times(j).mod(modulus); // j / (j - i)
			lambda = lambda.times(factor);
		}
		this.lambda = lambda;
	}
}

export class Shamir {
	static genShares(
		secret: BigInteger,
		shareCount: number,
		threshold: number,
		group: PrimeGroup,
	): Share[] {
		const randomPolyomial = ExponentPolynomial.randomPolynomial(
			secret,
			threshold - 1,
			group,
		);
		const shares = new Array<Share>(shareCount);
		for (let i = 1; i <= shareCount; i++) {
			shares[i - 1] = new Share(i, randomPolyomial.evaluate(i));
		}
		return shares;
	}

	static combineShares(
		shares: Share[],
		group: PrimeGroup,
		exponent: boolean = false,
	) {
		let mod = group.getModulus();
		let ord = group.getOrder();
		let at_0 = exponent ? bigInt(1) : bigInt(0);
		for (const share of shares) {
			if (!share.lambda) {
				share.calculateLambda(shares.length, ord);
			}
			at_0 = exponent
				? at_0.times(share.value.modPow(share.lambda!, mod)).mod(mod)
				: at_0.add(share.value.times(share.lambda!).mod(ord)).mod(ord);
		}
	}
}

export class Compartmented {
	static genShares(): Share[] {
		return [];
	}
}
