import bigInt from 'big-integer';
import { randomPrime, randomMod } from '../src/utils/commonUtils';

describe('randomPrime', () => {
	test('should generate a prime number of the specified bit length', () => {
		const bitLength = 16;
		const prime = randomPrime(bitLength);

		// Check that the generated number is of the correct bit length
		expect(prime.bitLength().toJSNumber()).toBeLessThanOrEqual(bitLength);

		// Check that the number is prime
		expect(prime.isProbablePrime()).toBeTruthy();
	});

	test('should generate a prime number that is likely prime for a given number of iterations', () => {
		const bitLength = 32;
		const iterations = 10;
		const prime = randomPrime(bitLength, iterations);

		// Check that the generated number is of the correct bit length
		expect(prime.bitLength().toJSNumber()).toBeLessThanOrEqual(bitLength);

		// Check that the number is prime with the specified certainty
		expect(prime.isProbablePrime(iterations)).toBeTruthy();
	});
});

describe('randomMod', () => {
	test('should generate a random number less than the modulus', () => {
		const modulus = bigInt(1000);
		const randomValue = randomMod(modulus);

		// Check that the generated value is in the correct range
		expect(randomValue.geq(modulus)).toBeFalsy();
		expect(randomValue.isNegative()).toBeFalsy();
	});

	test('should generate a random number of the correct bit length', () => {
		const modulus = bigInt(2).pow(256); // A 256-bit number
		const randomValue = randomMod(modulus);

		// Check that the bit length of the random number is less than or equal to the modulus' bit length
		expect(randomValue.bitLength().toJSNumber()).toBeLessThanOrEqual(256);
	});
});
