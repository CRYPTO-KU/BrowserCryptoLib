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
		let at_0 = exponent ? bigInt(1) : bigInt(0);
		for (const share of shares) {
			if (!share.lambda) {
				share.lambda = share.calculateLambda
			}
			at_0 = exponent ? at_0.mulMod(share.value.modPow(share.lambda?))
		}
	}
}

export class Compartmented {
	static genShares(): Share[] {
		return [];
	}
}
