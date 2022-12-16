const { group } = require("console")

const DEBUG = false //! Keep this FALSE for release. It prints out secret values.
const VERBOSE = false //! Keep this false as well.
/**
 * The functions accept and return values in base64 string format,
 * unless otherwise explicitly stated. This is to avoid confusion
 * while using them.
 */

// --- TESTS ---

function testAll(it=5) {
	let x = new BigIntegerAdapter(1234)
	let y = new BigIntegerAdapter(4321)
	print(x.toString())
	print(x.add(y).toString())
	print(x.times(y).toString())
	const groupTest = testGroup(it)
	const polTest = testPolynomials(it)
	const shamirTest = testShamir(3, 2, it)
}

function testPolynomials(it) {
	if (DEBUG) print("Testing polynomial operations.")
	const G = new PrimeGroup()
	console.time("Polynomial tests")
	for (let i = 1; i <= it; i++) {
		console.time("Polynomial test #"+i)
		const a0 = G.randomExponent()
		const pol = genPol(a0, 5*i, G)
		if (VERBOSE) {
			for (let i = 0; i < pol.length; i++) {
				const term = pol[i].toString()
				print(term + "x^" + i, newline=false)
			}
			print()
		}
		const eval_at_0 = evalPol(pol, 0, G)
		console.timeEnd("Polynomial test #"+i)
		if (a0.eq(eval_at_0)) continue
		print("Polynomial test failed.")
		if (DEBUG) {
			print("Constant term chosen:\n" + a0.toString())
			print("Constant term evaluated:\n" + eval_at_0.toString())
		}
		console.timeEnd("Polynomial tests")
		return false
	}
	console.timeEnd("Polynomial tests")
	if (DEBUG) print("Polynomial tests successful.")
	return true
}

function testShamir(n, t, it=1) {
	const G = new PrimeGroup()
	if (DEBUG) print("Testing Shamir's Secret Sharing.")
	console.time("Shamir tests")
	for (let i = 1; i <= it; i++) {
		console.time("Shamir test #"+i)
		const secret = G.randomExponent()
		const shares = shamirGenShares(secret, n*i, t*i, G)
		if (VERBOSE) {
			print("Generated shares:")
			for (const share of shares)
				print("\tShare #" + share[0] + ": " + share[1].toString())
		}
		const recons = shamirCombineShares(shares.slice(0, t*i), G)
		if (VERBOSE) {
			print("Secret reconstructed:")
			print("\tOriginal secret: " + secret.toString())
			print("\tReconstructed secret: " + recons.toString())
		}
		console.timeEnd("Shamir test #"+i)
		if (G.expEq(secret, recons)) continue
		print("Shamir's Secret Sharing tests failed at n=" + n*i + ", t=" + t*i + ".")
		print("Secret:\n" + secret.toString())
		print("Recons:\n" + recons.toString())
		console.timeEnd("Shamir tests")
		return false
	}
	console.timeEnd("Shamir tests")
	if (DEBUG) print("Shamir's Secret Sharing tests successful.")
	return true
}

function testGroup(it) {
	const G = new PrimeGroup()
	if (DEBUG) print("Testing inversion.")
	console.time("Group tests")
	for (let i = 1; i <= it; i++) {
		console.time("Group test #"+i)
		let x = G.randomElement()
		let x_inv = G.inverse(x)
		let e = G.mul(x, x_inv)
		console.timeEnd("Group test #"+i)
		if (e == 1) continue
		print("Inversion failed. e: " + e.toString())
		if (VERBOSE) {
			print("Random x: " + x.toString())
			print("Calculated x inverse: " + x_inv.toString())
		}
		console.timeEnd("Group tests")
		return false
	}
	console.timeEnd("Group tests")
	if (DEBUG) print("Inversion successful.")
	return true
}

//--- Tests end ---

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
	const bigInt = group.bigInt
	const n = shares.length
	let at0 = bigInt(0)
	for (const point of shares) {
		const i = point[0] // int, not bigInt
		const at_i = point[1]
		let lambda_i = bigInt(1)
		for (let j = 1; j <= n; j++) {
			if (i == j) continue
			const temp = group.expMul(j, bigInt(j-i).modInv(group.order)) // j/j-i
			lambda_i = group.expMul(lambda_i, temp)
		}
		at0 = group.expAdd(at0, group.expMul(at_i, lambda_i)) //! Legal only on exponents
	}
	return at0
}

function shamirGenShares(secret, n, t, group) {
	/**
	 * Takes a secret (that can be turned into bigInteger) and divides it into n shares
	 * with t of them necessary and sufficient to reveal the secret.
	 */
	const bigInt = group.bigInt
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
	 * a_0 = secret, needs to be in the exponent range
	 * a_i = random for all 0<i<t
	 * All elements are exponents in the given group represented as bigIntegers
	 */
	if (group.order.leq(secret)) //? This really should not be the case. Maybe throw instead?
		secret = secret.mod(group.order) //? Care about negatives?
	const pnomial = [secret]
	for (let i = 1; i < t; i++) {
		pnomial.push(group.randomExponent())
	}
	return pnomial
}

function evalPol(pol, x, group) {
	/**
	 * Evaluates the polynomial at x in the exponents of the given group
	 */
	let sum = 0
	for(let i = 0; i < pol.length; i++) {
		const x_i = group.expMul(pol[i], group.expPow(x, i))
		sum = group.expAdd(sum, x_i)
	}
	return sum
}
//--- Secret Sharing end ---

//--- OPRF functions ---
// These functions return big integers instead of base16 strings

async function oprfResponse(beta, ro, group) {
	return group.pow(beta, group.inverse(ro))
}

async function oprfChallenge(alpha, k, group) {
	/**
	 * Return beta = alpha^k mod p as a string.
	 */
	return group.pow(alpha, k)
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
	const bigInt = group.bigInt
	const ro = group.randomElement()
	const Hp_x = await hashPrime(secret, group)
	if(DEBUG) print("Hp_x: " + Hp_x)
	const Hp_xToRo = group.pow(bigInt(Hp_x, 16), ro) //TODO: Get group to accept bases
	return [ro, Hp_xToRo]
}
//--- OPRF end ---

//--- Hash functions ---
async function hashPrime(str, group) { //* Full domain hash, problem: Z_n*
	/**
	 * Hashes a string to an element in the given group.
	 * Returns a promise resolving to the hash as a hex string.
	 * This is not fixed sized output, though.
	 */
	const bigInt = group.bigInt
	let baseHash = await hash(str) // Hex string
	baseHash = bigInt(baseHash, 16).mod(group.order) // bigInt
	let hp = group.pow(group.generator, baseHash) // bigInt
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

class PrimeGroup {
	// We work on a fixed group with generator 2.
	// ! Hardcoding may be problematic for any sort of production code.
	// TODO: Reduce the size of this group
	constructor(modulus=0, generator=0, order=0) {
		const bigInt = require("big-integer")
		if(modulus==0) { //* Order 256-bit (or 512-bit)
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
			//modulus = bigInt(23)
			//order = bigInt(11)
		}
		this.modulus = new bigInt(modulus)
		this.generator = new bigInt(generator)
		this.order = new bigInt(order)
		this.bigInt = bigInt // This allows for easier alteration of bigInt library.
	}

	inverse(elm) {
		/**
		 * Returns the inverse of elm in group.
		 * Employs the fact that elm^order = 1 so elm^(order-1) = elm^(-1)
		 */
		return this.pow(this.bigInt(elm), this.expSubtract(this.order, 1))
	}

	expInverse(exp) { //! BUG
		/**
		 * Returns the inverse of exponent, so that:
		 * g^{exp} * g^{exp^-1} = g
		 */
		return this.pow(this.bigInt(exp), this.expSubtract(this.order, 2))
	}
	
	randomElement() {
		/**
		 * Returns a random element in the given group.
		 * Employs getRandomMod.
		 */
		return this.pow(this.generator, this.randomExponent())
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
		let rnd = Crypto.getRandomValues(new Uint8Array(32)) // ArrayBuffer
		rnd = Buffer.from(rnd).toString('hex') // Hex
		return this.bigInt(rnd, 16).mod(this.order) // bigInt
	}
	mul(x, y) { // TODO: Check the efficiency here
		return this.bigInt(x).times(this.bigInt(y)).mod(this.modulus)
	}

	expMul(x, y) { // TODO: Check the efficiency here
		return this.bigInt(x).times(this.bigInt(y)).mod(this.order)
	}

	add(x, y) {  //! This group is not additive, be careful
		if(DEBUG) print("You are adding elements in a multiplicative group, are you sure?")
		return this.bigInt(x).add(this.bigInt(y)).mod(this.modulus)
	}

	subtract(x, y) { //! This group is not additive, be careful
		if(DEBUG) print("You are subtracting elements in a multiplicative group, are you sure?")
		var cand = this.bigInt(x).subtract(this.bigInt(y)).mod(this.modulus)
		return cand.leq(0) ? cand.add(this.modulus) : cand
	}

	expAdd(x, y) {
		return this.bigInt(x).add(this.bigInt(y)).mod(this.order)
	}

	expSubtract(x, y) {
		var cand = this.bigInt(x).subtract(this.bigInt(y)).mod(this.order)
		return cand.leq(0) ? cand.add(this.order) : cand
	}

	pow(x, y) { // TODO: Check the efficiency here
		return this.bigInt(x).modPow(this.bigInt(y), this.modulus)
	}

	expPow(x, y) { // TODO: Check the efficiency here
		return this.bigInt(x).modPow(this.bigInt(y), this.order)
	}

	eq(x, y) {
		// TODO: Check whether elements always map into groups
		// TODO: Add a map-into-group call
		const bigInt = this.bigInt
		// Mod into group
		var temp_x = bigInt(x).mod(this.modulus)
		var temp_y = bigInt(y).mod(this.modulus)
		// Check positivity
		temp_x = temp_x.leq(0) ? temp_x.add(this.modulus) : temp_x
		temp_y = temp_y.leq(0) ? temp_y.add(this.modulus) : temp_y
		return temp_y.eq(temp_x)
	}

	expEq(x, y) {
		// TODO: Check whether elements always map into groups
		// TODO: Add a map-into-group call
		const bigInt = this.bigInt
		// Mod into group
		var temp_x = bigInt(x).mod(this.order)
		var temp_y = bigInt(y).mod(this.order)
		// Check positivity
		temp_x = temp_x.leq(0) ? temp_x.add(this.order) : temp_x
		temp_y = temp_y.leq(0) ? temp_y.add(this.order) : temp_y
		return temp_y.eq(temp_x)
	}
}

class BigIntegerAdapter {
	constructor(value) {
		this.bigInt = require('big-integer')
		this.value = this.bigInt(value)
	}
	// Base calls
	add(num) {
		return new BigIntegerAdapter(this.value.add(num.value))
	}
	subtract(num) {
		return new BigIntegerAdapter(this.value.subtract(num.value))
	}
	mul(num) {
		return new BigIntegerAdapter(this.value.times(num.value))
	}
	times(num) {
		return this.mul(num)
	}
	pow(num) {
		return new BigIntegerAdapter(this.value.pow(num.value))
	}
	eq(num) {
		return this.value.eq(num.value)
	}
	leq(num) {
		return his.value.leq(num.value)
	}
	geq(num) {
		return this.value.geq(num.value)
	}
	lesser(num) {
		return this.value.lesser(num.value)
	}
	greater(num) {
		return this.value.greater(num.value)
	}
	// Mod calls, return positive
	mod(mod) {
		var result = new BigIntegerAdapter(this.value.mod(mod))
		return result.lesser(0) ? result.add(mod) : result
	}
	addMod(num, mod) {
		return this.add(num).mod(mod)
	}
	subtractMod(num, mod) {
		return this.subtract(num).mod(mod)
	}
	mulMod(num, mod) {
		return this.mul(num).mod(mod)
	}
	powMod(num, mod) {
		return this.pow(num).mod(mod)
	}
	eqMod(num, mod) {
		x = this.mod(mod)
		y = num.mod(mod)
		return x.eq(y)
	}
	invMod(mod) {
		return new BigIntegerAdapter(this.value.modInv(mod))
	}
	// Other functionalities
	toString() {
		return this.value.toString()
	}
}

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
    testAll();
}