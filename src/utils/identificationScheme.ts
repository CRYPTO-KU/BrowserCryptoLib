import { PrimeGroup } from '../group';
import { BigInteger } from './commonUtils';

export class Schnorr {
	static createChallenge(group: PrimeGroup) {
		return group.randomExponent();
	}

	static calculateResponse(
		secret: BigInteger,
		challenge: BigInteger,
		group: PrimeGroup,
	): {
		pubKey: BigInteger;
		randomElement: BigInteger;
		response: BigInteger;
	} {
		const mod = group.getModulus();
		const ord = group.getOrder();
		const gen = group.getGenerator();

		const pubKey = gen.modPow(secret, mod);
		const randExp = group.randomExponent();
		const randElm = gen.modPow(randExp, mod);
		const resp = randExp.add(secret.times(challenge)).mod(ord);

		return {
			pubKey: pubKey,
			randomElement: randElm,
			response: resp,
		};
	}

	static verify(
		publicKey: BigInteger,
		randomElement: BigInteger,
		response: BigInteger,
		challenge: BigInteger,
		group: PrimeGroup,
	): boolean {
		const mod = group.getModulus();
		const received = group.getGenerator().modPow(response, mod);
		const expected = randomElement
			.times(publicKey.modPow(challenge, mod))
			.mod(mod);
		return received.equals(expected);
	}
}
