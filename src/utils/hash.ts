import bigInt from 'big-integer';
import { PrimeGroup } from '../group';
import { BigInteger, bytesToHex } from './commonUtils';
import { getCryptoAPI } from './cryptoUtils';

const cryptoAPI = await getCryptoAPI();
const enc = new TextEncoder();

export async function groupHash(
	input: BigInteger,
	group: PrimeGroup,
): Promise<BigInteger> {
	// ! This function is dangerously rushed.
	const gen = group.getGenerator();
	const ord = group.getOrder();
	let hashBuffer = await cryptoAPI.subtle.digest(
		'SHA-512',
		enc.encode(input.toString(16)),
	);
	const hashBytes = new Uint8Array(hashBuffer);
	const hashHex = bytesToHex(hashBytes);
	const hashBigInt = bigInt(hashHex, 16);
	const hashMappedToGroup = gen.modPow(hashBigInt, ord);
	return hashMappedToGroup;
}
