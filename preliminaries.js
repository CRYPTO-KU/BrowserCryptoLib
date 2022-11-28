const DEBUG = true //! Keep this FALSE for release. It prints out secret values.
const VERBOSE = false //! Keep this false as well.
/**
 * The functions accept and return values in base64 string format,
 * unless otherwise explicitly stated. This is to avoid confusion
 * while using them.
 */

function main() {
	// testShamir("19823769182637", 5, 3)
	testGroup(10)
}

function testShamir(secret, n, t, it=1) {
	// TODO: Time the tests.
	print("Testing random polynomial and evaluation.")
	const G = new PrimeGroup()
	for (let i = 1; i <= it; i++) {
		const secret = G.randomElement()
		const pol = genPol("123456", 5, G)
		if(VERBOSE) {
			for (let i = 0; i < pol.length; i++) {
				const term = pol[i].toStrig()
				print(term + "x^" + i, newline=false)
			}
			print()
		}

	}
	const shares = shamirGenShares(secret, n, t, G)
	print("Generated shares:")
	for (const share of shares)
		print("\tShare #" + share[0].toString() + ": " + share[1].toString())
	const reconst = shamirCombineShares(shares, G)
	print("Secret reconstructed:")
	print("\tOriginal secret: " + secret.toString())
	print("\tReconstructed secret: " + reconst.toString())
}

function testGroup(it) {
	// TODO: Time the tests.
	const G = new PrimeGroup()
	print("Testing invert operation randomly " + it + " times: ")
	for (let i = 1; i <= it; i++) {
		let x = G.randomElement()
		let x_inv = G.inverse(x)
		let e = x.times(x_inv).mod(G.modulus)
		if (e == 1) continue
		print("Inversion failed. e: " + e.toString())
		if(VERBOSE) {
			print("Random x: " + x.toString())
			print("Calculated x inverse: " + x_inv.toString())
		}
	}
	print("Inversion successful.")
}

class PrimeGroup {
	// We work on a fixed group with generator 2.
	// ! This may be problematic for any sort of production code.
	constructor(modulus=0, generator=0, order=0) {
		const bigInt = require("big-integer")
		if(modulus==0) {
			// https://datatracker.ietf.org/doc/rfc3526/ | Group id 15
			modulus = new bigInt( // prime modulus
				"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
				"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
				"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
				"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
				"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
				"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
				"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
				"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
				"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
				"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
				"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"+
				"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"+
				"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"+
				"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"+
				"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"+
				"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16)
			order = modulus.subtract(1).divide(2) // order of generator
			generator = new bigInt(2) // generator = 2
		}
		this.modulus = new bigInt(modulus)
		this.generator = new bigInt(generator)
		this.order = new bigInt(order)
	}

	inverse(elm) {
		/**
		 * Returns the inverse of elm in group.
		 * Employs the fact that elm^order = 1 so elm^(order-1) = elm^(-1)
		 */
		return bigInt(elm).modPow(this.order.subtract(1), this.modulus)
	}
	
	randomElement() {
		/**
		 * Returns a random element in the given group.
		 * Employs getRandomMod.
		 */
		return this.generator.modPow(getRandomMod(this.order), this.modulus)
	}
	
	randomExponent() {
		/**
		 * Returns a random bigInt between 1 and order.
		 * ! NOT SECURE YET, BUT WORKS NICELY ENOUGH. NEED TO TAKE CARE OF BIASING.
		 */
		let Crypto
		if (typeof require !== 'undefined' && require.main === module) {
			Crypto = require('crypto')
		} else {
			Crypto = self.crypto
		}
		rnd = Crypto.getRandomValues(new Uint8Array(32)) // ArrayBuffer
		rnd = Buffer.from(rnd).toString('hex') // Hex
		return bigInt(rnd, 16).mod(this.order) // bigInt
	}

	mul(x, y) {
		//* This can likely be made more efficient
		return bigInt(x).times(y).mod(this.modulus)
	}

	add(x, y) {
		return bigInt(x).add(y).mod(this.modulus)
	}

	subtract(x, y) {
		return bigInt(x).subtract(y).mod(this.modulus)
	}
}

//--- Secret Sharing functions ---
function shamirCombineShares(shares, group) {
	/**
	 * Takes an array of indices and shares where the elements
	 * are in the form [k, share #k]. Uses Lagrange interpolation
	 * to combine the shares and returns the secret as a BigInteger.
	 * * Does not check for n, t values! If not enough shares are
	 * * given, simply returns a wrong value. Giving more than enough
	 * * shares does not change the output.
	 */
	const bigInt = require('big-integer')
	const n = shares.length

	let at0 = bigInt(0)
	for (const point of shares) {
		const x = point[0]
		const share_x = point[1]
		let lambda_i = bigInt(1)
		for (let j = 1; j <= n; j++) {
			if (x == j) continue
			const temp = bigInt(j).times(inverse(bigInt(j).subtract(x), group)).mod(group.modulus)
			lambda_i = lambda_i.times(temp).mod(group.modulus)
		}
		at0 = at0.add(share_x.times(lambda_i).mod(group.modulus)).mod(group.modulus)
	}
	return at0
}

function shamirGenShares(secret, n, t, group) {
	/**
	 * Takes a secret (that can be turned into bigInteger) and divides it into n shares
	 * with t of them necessary and sufficient to reveal the secret.
	 */
	const bigInt = require('big-integer')
	const pnomial = genPol(bigInt(secret), t, group)
	const shares = []
	for (let i = 1; i <= n; i++) {
		shares.push([i, evalPol(pnomial, i, group)])
	}
	return shares
}

function genPol(secret, t, group) {
	/**
	 * Constructs a degree t-1 polynomial where
	 * a_0 = secret
	 * a_i = random for all 0<i<t
	 * All elements are bigIntegers in the given group
	 */
	const pnomial = [secret]
	for (let i = 0; i < t; i++) {
		const pow = getRandomMod(group.order) // Random exponent
		pnomial.push(group.generator.modPow(pow, group.modulus)) // Random group element, mod operation probably unnecessary
	}
	return pnomial
}

function evalPol(pol, x, group) {
	/**
	 * Evaluates the polynomial at x. Always stays in the group.
	 * * Perhaps times().mod() can be more efficient by taking mod at each step.
	 */
	const bigInt = require('big-integer')
	let sum = bigInt(0)
	for(let i = 0; i < pol.length; i++) {
		const x_i = pol[i].times(bigInt(x).modPow(i, group.modulus)).mod(group.modulus)
		sum = sum.add(x_i).mod(group.modulus)
	}
	return sum
}
//--- Secret Sharing end ---

//--- OPRF functions ---
// These functions return big integers instead of base16 strings

async function oprfResponse(beta, ro, group) {
	roInv = ro.modInv(group.modulus)
	return beta.modPow(roInv, group.modulus)
}

async function oprfChallenge(alpha, k, group) {
	/**
	 * Return beta = alpha^k mod p as a string.
	 */
	return alpha.modPow(k, group.modulus)
}
	
async function oprfMask(secret, group) {
	/**
	 * Creates the masked text to be sent to each SP.
	 * Call this function once, and send alpha to each SP.
	 * This returns a promise resolving to [ro, alpha], the SPs will responds with
	 * beta_i = alpha^k_i and will also send c_i
	 * This function also returns ro, which should be kept secret and only 
	 * be used as an input to the reconstructPassword function.
	 * @returns [ro, alpha]
	 */
	const bigInt = require('big-integer')
	const ro = getRandomMod(group.order)
	const Hp_x = await hashPrime(secret, group)
	if(DEBUG) print("Hp_x: " + Hp_x)
	const Hp_xToRo = bigInt(Hp_x, 16).modPow(ro, group.modulus)
	return [ro, Hp_xToRo]
}
//--- OPRF end ---

//--- Hash functions ---
async function hashPrime(str, group) {
	/**
	 * Hashes a string to an element in the given group.
	 * Returns a promise resolving to the hash as a hex string.
	 */
	const bigInt = require('big-integer')
	let baseHash = await hash(str) // Hex string
	baseHash = new bigInt(baseHash, 16) // bigInt
	baseHash = baseHash.mod(group.order) // bigInt
	let hp = bigInt(group.generator).modPow(baseHash, group.modulus) // bigInt
	hp = hp.toString(16) // Hex string
	while(hp.length < 32) hp = "0" + hp // Converstion to string may reduce size only when there are 0s on the left side
	return hp
}
async function hash(str) {
	/**
	 * Hashes a string using SHA-256, returns a promise resolving to the hash as a string.
	 */
	const enc = new TextEncoder()
	const data = enc.encode(str)
	let Crypto
	if (typeof require !== 'undefined' && require.main === module) {
		Crypto = require('crypto')
	} else {
		Crypto = self.crypto
	}
	let hash = await Crypto.subtle.digest("SHA-256", data)
	hash = Buffer.from(hash).toString("hex")
	if(hash.length != 64) print("Error: Hash is not 256 bits: l= " + hash.length*4, color="red")
	return hash
}
//--- Hash end ---

//--- Some helpful functions ---

function toArrayBuffer(buf) {
	/**
	 * This is a simple function that transforms Buffer data into BufferArray data.
	 */
    const ab = new ArrayBuffer(buf.length);
    const view = new Uint8Array(ab);
    for (let i = 0; i < buf.length; i++) {
        view[i] = buf[i];
    }
    return ab;
}

function print(T='', newline=true, html=false, color="") {
	/**
	 * This is a shorthand function for printing to the console or the process.
	 * The coloring only works on console printing with newline, because I am lazy.
	 */
	if(color!="")
		console.log("%c" + T, "color: " + color)
	else if(!newline)
		process.stdout.write(T)
	else if(html)
		document.write(T)
	else
		console.log(T)
}
//--- Helpful functions end ---

// This check protects from imports running main().
if (typeof require != 'undefined' && require.main == module) {
    main();
}