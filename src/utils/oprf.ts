import { PrimeGroup } from '../group';
import { BigInteger } from './commonUtils';
import { LogicError } from './errors';
import { groupHash } from './hash';
import { Shamir, Share } from './secretSharing';

export async function mask(
	secret: BigInteger,
	group: PrimeGroup,
): Promise<{ maskRandom: BigInteger; mask: BigInteger }> {
	const rho = group.randomElement();
	const alpha = (await groupHash(secret, group)).modPow(
		rho,
		group.getModulus(),
	);
	return { maskRandom: rho, mask: alpha };
}

export function processMask(
	mask: BigInteger,
	key: BigInteger,
	group: PrimeGroup,
): BigInteger {
	return mask.modPow(key, group.getModulus());
}

export function unmask(
	processedMask: BigInteger,
	maskRandom: BigInteger,
	group: PrimeGroup,
): BigInteger {
	return processedMask.modPow(
		maskRandom.modInv(group.getOrder()),
		group.getModulus(),
	);
}

export function thresholdUnmask(
	processedMasks: Share[],
	maskRandom: BigInteger,
	group: PrimeGroup,
): BigInteger {
	for (const share of processedMasks) {
		if (share.lambda) {
			throw new LogicError({
				name: 'UNEXPECTED_PRECOMPUTATION',
				message:
					'Interpolation lambda precalculated before unmasking the values',
				cause: thresholdUnmask,
			});
		}
		share.value = unmask(share.value, maskRandom, group);
	}
	return Shamir.combineShares(processedMasks, group, true);
}
