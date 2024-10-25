import bigInt from 'big-integer';
import { getCryptoAPI } from './cryptoUtils';

export type BigInteger = bigInt.BigInteger;
const Crypto = await getCryptoAPI();

const byteToHex: string[] = [];

for (let n = 0; n <= 0xff; n++) {
  const hexOctet = n.toString(16).padStart(2, '0');
  byteToHex.push(hexOctet);
}

/**
 * @brief Converts a Uint8Array to a hexadecimal string. Does not mutate the elements
 * of the input array.
 * @param byteArray
 * @returns Hexadecimal representation of bytes in byteArray
 */
export function BytesToHex(byteArray: Uint8Array) {
  /**
   * Credit to: https://stackoverflow.com/questions/40031688/how-can-i-convert-an-arraybuffer-to-a-hexadecimal-string-hex
   */
  const hexOctets = new Array(byteArray.length);
  for (let i = 0; i < byteArray.length; i++) {
    hexOctets[i] = byteToHex[byteArray[i]];
  }
  return hexOctets.join('');
}

export function randomBigInteger(
  bitLength: number,
  force: boolean = false,
): BigInteger {
  // Get the suitable Crypto API for the environment
  // Create enough cryptographically random bits
  const byteLength = Math.ceil(bitLength / 8);
  let rnd = Crypto.getRandomValues(new Uint8Array(byteLength));

  // Remove unwanted bits through masking
  const necessaryBits = 8 - (byteLength * 8 - bitLength);
  rnd[0] = rnd[0] & parseInt('1'.repeat(necessaryBits), 2);

  if (force) {
    // Set the first bit to 1
    // TODO: Is this necessary?
    rnd[0] = rnd[0] | parseInt('1' + '0'.repeat(necessaryBits - 1), 2);
  }

  return bigInt(BytesToHex(rnd));
}

export function randomPrime(
  bitLength: number,
  iterations: number = 5,
): BigInteger {
  // * Potential bottleneck
  // TODO: What is a good number for iterations?
  let rand: BigInteger;
  do {
    rand = randomBigInteger(bitLength, true);
  } while (!rand.isProbablePrime(iterations));
  return rand;
}

/**
 * Generates a random number between 0 and modulus - 1 using
 * rejection sampling.
 * @param modulus
 * @returns
 */
export function randomMod(modulus: BigInteger): BigInteger {
  let rnd: BigInteger;
  do {
    rnd = randomBigInteger(modulus.bitLength().toJSNumber(), false);
  } while (rnd.geq(modulus));
  return rnd;
}
