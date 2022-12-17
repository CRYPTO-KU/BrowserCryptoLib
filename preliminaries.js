const { group } = require("console")
const { truncate } = require("fs")
const { BigInteger } = require("jsbn")

const DEBUG = false //! Keep this FALSE for release. It prints out secret values.
const VERBOSE = false //! Keep this false as well.

// --- TESTS ---

function testAll(it=5) {
	const groupTest = testGroup(it)
	const polTest = testPolynomials(it)
	const baseShamirTest = testShamir(3, 2, it, false)
	const exponentShamirTest = testShamir(3, 2, it, true)
	const OPRFTest = testOPRF("Meaning of life")
}

async function testOPRF(secret, exponent=false) {
	const G = new PrimeGroup()
	console.time((exponent ? "t-" : "") + "OPRF test")
	var Hp_x = await hashPrime(secret, G)
	Hp_x = new BigIntegerAdapter(Hp_x, 16)
	const [ro, alpha] = await oprfMask(secret, G)
	const k = G.randomExponent()
	const beta = await oprfChallenge(alpha, k, G)
	const resp = await oprfResponse(beta, ro, G)
	check = Hp_x.powMod(k, G.modulus).eqMod(resp, G.modulus)
	if (DEBUG) {
		print(`ro: ${ro.toString()} \t`)
		print(`alpha: ${alpha.toString()} \t`)
		print(`beta: ${beta.toString()} \t`)
		print(`resp: ${resp.toString()} \t`)
	}
	console.timeEnd((exponent ? "t-" : "") + "OPRF test")
	print((exponent ? "t-" : "") + "OPRF test " + (check ? "successful." : "failed."))
	return check
}

function testShamir(n, t, it, exponent=false) {
	const G = new PrimeGroup()
	const modulus = G.modulus
	const order = G.order
	if (DEBUG) print("Testing Shamir's Secret Sharing on " + (exponent ? "exponent" : "base"))
	console.time("Shamir tests")
	for (let i = 1; i <= it; i++) {
		console.time("Test #" + i + ": n=" + n*i + ", t=" + t*i)
		const secret = G.randomExponent()
		const shares = shamirGenShares(secret, n*i, t*i, G)
		if (VERBOSE) {
			print("Generated shares:")
			for (const share of shares)
				print("\tShare #" + share[0] + ": " + share[1].toString())
		}
		if (exponent) {
			let elm = G.randomElement()
			var secret_elm = elm.powMod(secret, modulus)
			for (var share of shares) 
				share[1] = elm.powMod(share[1], modulus)
			
		}
		const recons = shamirCombineShares(shares.slice(0, t*i), G, exponent)
		if (VERBOSE) {
			print("Secret reconstructed:")
			print("\tOriginal secret: " + secret.toString())
			print("\tReconstructed secret: " + recons.toString())
		}
		console.timeEnd("Test #" + i + ": n=" + n*i + ", t=" + t*i)
		var check = exponent ? secret_elm.eqMod(recons, modulus) : secret.eqMod(recons, order)
		if (check) continue
		print("Shamir's Secret Sharing tests failed at n=" + n*i + ", t=" + t*i + ", on " + (exponent ? "exponent" : "base"))
		print("Secret:\n" + secret.toString())
		print("Recons:\n" + recons.toString())
		console.timeEnd("Shamir tests")
		return false
	}
	console.timeEnd("Shamir tests")
	if (DEBUG) print("Shamir's Secret Sharing tests on " + (exponent ? "exponent" : "base") + " successful.")
	return true
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

function testGroup(it) {
	const G = new PrimeGroup()
	if (DEBUG) print("Testing inversion.")
	console.time("Group tests")
	for (let i = 1; i <= it; i++) {
		console.time("Group test #"+i)
		let x = G.randomElement()
		let x_inv = x.invMod(G.modulus)
		let e = x.mulMod(x_inv, G.modulus)
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
	if (DEBUG) print("Group tests successful.")
	return true
}

//--- Tests end ---

//--- Secret Sharing functions ---
function shamirCombineShares(shares, group, exponent=false) {
	/**
	 * Takes an array of indices and shares where the elements
	 * are in the form [k, share #k]. Uses Lagrange interpolation
	 * to combine the shares and returns the secret as a BigInteger.
	 * * Does not check for n, t values! If not enough shares are
	 * * given, simply returns a wrong value. Giving more than enough
	 * * shares does not change the output.
	 */
	const n = shares.length
	const mod = group.modulus
	const ord = group.order
	let at_0 = exponent ? new BigIntegerAdapter(1) : new BigIntegerAdapter(0)
	for (const point of shares) {
		const i = point[0] // int, not bigInt
		const at_i = point[1]
		let lambda_i = new BigIntegerAdapter(1)
		for (let j = 1; j <= n; j++) {
			if (i == j) continue
			const inv = (new BigIntegerAdapter(j-i)).invMod(ord) // 1/j-i
			const temp = inv.mulMod(j, ord) // j/j-i
			lambda_i = lambda_i.mulMod(temp, ord)
		}
		if (exponent) at_0 = at_0.mulMod(at_i.powMod(lambda_i, mod), mod)
		else at_0 = at_0.addMod(at_i.mulMod(lambda_i, ord), ord) //* Exponent group is additive
	}
	return at_0
}

function shamirGenShares(secret, n, t, group) {
	/**
	 * Takes a secret (that can be turned into bigInteger) and divides it into n shares
	 * with t of them necessary and sufficient to reveal the secret.
	 */
	const pnomial = genPol(new BigIntegerAdapter(secret), t, group)
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
	const pnomial = [secret]
	for (let i = 1; i < t; i++) {
		const rand = group.randomExponent()
		pnomial.push(rand)
	}
	return pnomial
}

function evalPol(pol, x, group) {
	/**
	 * Evaluates the polynomial at x in the exponents of the given group
	 */
	x = new BigIntegerAdapter(x)
	const mod = group.order
	let sum = new BigIntegerAdapter(0)
	for(let i = 0; i < pol.length; i++) {
		const x_i = pol[i].mulMod(x.powMod(i, mod), mod)
		sum = sum.addMod(x_i, mod)
	}
	return sum
}
//--- Secret Sharing end ---

//--- OPRF functions ---

async function oprfResponse(beta, ro, group) {
	/**
	 * Return beta^(ro^-1) = alpha^(k*(ro^-1)) = Hp_x^(ro*k*(ro^-1)) = Hp_x^k
	 */
	return beta.powMod(ro.invMod(group.order), group.modulus)
}

async function oprfChallenge(alpha, k, group) {
	/**
	 * Return beta = alpha^k mod p as a string.
	 */
	return alpha.powMod(k, group.modulus)
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
	const ro = group.randomElement()
	const Hp_x = await hashPrime(secret, group)
	if(VERBOSE) print("Hp_x: " + Hp_x)
	var Hp_xToRo = new BigIntegerAdapter(Hp_x, 16)
	Hp_xToRo = Hp_xToRo.powMod(ro, group.modulus)
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
	const g = group.generator
	const mod = group.modulus
	let baseHash = await hash(str) // Hex string
	baseHash = new BigIntegerAdapter(baseHash, 16)
	baseHash = baseHash.mod(group.order) // bigInt
	let hp = g.powMod(baseHash, mod) // bigInt
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
		if(modulus==0) { //* Order 256-bit (or 512-bit)
			// https://datatracker.ietf.org/doc/rfc3526/ | Group id 15
			modulus = new BigIntegerAdapter( // prime modulus
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
			generator = new BigIntegerAdapter(2) // generator = 2
			// modulus = new BigIntegerAdapter(23)
			// order = new BigIntegerAdapter(11)
		}
		this.modulus = new BigIntegerAdapter(modulus)
		this.generator = new BigIntegerAdapter(generator)
		this.order = new BigIntegerAdapter(order)
	}
	randomExponent() {
		/**
		 * Returns a random bigInt between 1 and order.
		 * ! NOT SECURE YET, BUT WORKS NICELY ENOUGH. NEED TO TAKE CARE OF BIASING.
		 */
		// Get a random number
		let Crypto
		if (typeof require !== 'undefined' && require.main === module) {
			Crypto = require('crypto')
		} else {
			Crypto = self.crypto
		}
		let rnd = Crypto.getRandomValues(new Uint8Array(32)) // ArrayBuffer
		rnd = Buffer.from(rnd).toString('hex') // Hex
		// Transform to BigIntegerAdapter
		rnd = new BigIntegerAdapter(rnd, 16)
		return rnd.mod(this.order)
	}
	randomElement() {
		/** Returns a random group element */
		return this.generator.powMod(this.randomExponent(), this.modulus)
	}
}

class BigIntegerAdapter {
	constructor(value, radix=10) {
		this.bigInt = require('big-integer')
		if (value instanceof BigIntegerAdapter) this.value = value.value
		else this.value = this.bigInt(value, radix)
	}
	// Base calls
	add(num) {
		if (Number.isInteger(num)) num = new BigIntegerAdapter(num)
		return new BigIntegerAdapter(this.value.add(num.value))
	}
	subtract(num) {
		if (Number.isInteger(num)) num = new BigIntegerAdapter(num)
		return new BigIntegerAdapter(this.value.subtract(num.value))
	}
	mul(num) {
		if (Number.isInteger(num)) num = new BigIntegerAdapter(num)
		return new BigIntegerAdapter(this.value.times(num.value))
	}
	times(num) {
		return this.mul(num)
	}
	divide(num) {
		if (Number.isInteger(num)) num = new BigIntegerAdapter(num)
		return new BigIntegerAdapter(this.value.divide(num.value))
	}
	pow(num) {
		if (Number.isInteger(num)) num = new BigIntegerAdapter(num)
		return new BigIntegerAdapter(this.value.pow(num.value))
	}
	eq(num) {
		if (Number.isInteger(num)) num = new BigIntegerAdapter(num)
		return this.value.eq(num.value)
	}
	leq(num) {
		if (Number.isInteger(num)) num = new BigIntegerAdapter(num)
		return this.value.leq(num.value)
	}
	geq(num) {
		if (Number.isInteger(num)) num = new BigIntegerAdapter(num)
		return this.value.geq(num.value)
	}
	lesser(num) {
		if (Number.isInteger(num)) num = new BigIntegerAdapter(num)
		return this.value.lesser(num.value)
	}
	greater(num) {
		if (Number.isInteger(num)) num = new BigIntegerAdapter(num)
		return this.value.greater(num.value)
	}
	// Mod calls, return positive
	mod(mod) {
		if (Number.isInteger(mod)) mod = new BigIntegerAdapter(mod)
		var result = new BigIntegerAdapter(this.value.mod(mod.value))
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
		if (Number.isInteger(num)) num = new BigIntegerAdapter(num)
		if (Number.isInteger(mod)) mod = new BigIntegerAdapter(mod)
		return new BigIntegerAdapter(this.value.modPow(num.value, mod.value))
	}
	eqMod(num, mod) {
		if (Number.isInteger(num)) num = new BigIntegerAdapter(num)
		if (Number.isInteger(mod)) mod = new BigIntegerAdapter(mod)
		let value = this.mod(mod)
		num = num.mod(mod)
		return value.eq(num)
	}
	invMod(mod) {
		if (Number.isInteger(mod)) mod = new BigIntegerAdapter(mod)
		return new BigIntegerAdapter(this.value.modInv(mod.value))
	}
	// Other functionalities
	toString(radix=10) {
		return this.value.toString(radix)
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

// This check protects importing scripts from running main().
if (typeof require != 'undefined' && require.main == module) {
    testAll();
}