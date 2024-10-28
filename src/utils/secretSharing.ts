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
	): BigInteger {
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
		return at_0;
	}
}

export class ShareCompartment {
	constructor(
		public size: number,
		public threshold: number,
		public shares: Share[] = new Array<Share>(size),
	) {}
}

export class Compartmented {
	static genShares(
		secret: BigInteger,
		compartments: ShareCompartment[],
		group: PrimeGroup,
	): ShareCompartment[] {
		const ord = group.getOrder();
		// Calculate compartment secrets so that their sum equals the original secret.
		const compartmentSecrets = new Array<BigInteger>(compartments.length);
		let secretSum = bigInt(0);
		for (let i = 0; i < compartments.length - 1; i++) {
			const compartmentSecret = group.randomExponent();
			secretSum = secretSum.add(compartmentSecret).mod(ord);
			compartmentSecrets[i] = compartmentSecret;
		}
		let lastSecret = secret.subtract(secretSum);
		while (lastSecret.isNegative()) {
			lastSecret.add(ord);
		}
		lastSecret = lastSecret.mod(ord); // Probably unnecessary, but just in case.
		compartmentSecrets[compartmentSecrets.length - 1] = lastSecret;
		for (let i = 0; i < compartments.length; i++) {
			const compartment = compartments[i];
			compartment.shares = Shamir.genShares(
				compartmentSecrets[i],
				compartment.size,
				compartment.threshold,
				group,
			);
		}
		return compartments;
	}

	static combineShares(
		compartmentShares: Share[][],
		group: PrimeGroup,
	): BigInteger {
		let secret = bigInt(0);
		for (let i = 0; i < compartmentShares.length; i++) {
			const compartmentSecret = Shamir.combineShares(
				compartmentShares[i],
				group,
			);
			secret = secret.add(compartmentSecret).mod(group.getOrder());
		}
		return secret;
	}
}
