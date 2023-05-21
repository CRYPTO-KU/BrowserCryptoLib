/* eslint-disable camelcase */

const { assert } = require('console');

// ! Keep the below false for release. They print out secret values.
const DEBUG = false;
const VERBOSE = false;
iterations = 0;
// --- TESTS ---

// eslint-disable-next-line require-jsdoc
function manualTest() {
  console.time('Random Prime Generation');
  const G = new PrimeGroup(2048, 256, 1);
  console.timeEnd('Random Prime Generation');
  print('New PrimeGroup generated.');
  print('Modulus: ' + G.modulus.toString(16));
  print('Order: ' + G.order.toString(16));
  print('Generator: ' + G.generator.toString(16));
}


/**
 * Runs all tests.
 * @param {int} it Iteration count
 */
async function testAll(it=5) {
  const secret = 'Meaning of life.';
  console.time('\nTotal runtime for tests');
  const groupTest = testGroup(it);
  const polTest = testPolynomials(it);
  const baseShamirTest = testShamir(3, 2, it, false);
  const exponentShamirTest = testShamir(3, 2, it, true);
  const OPRFTest = await testOPRF(secret);
  const tOPRFTest = await testT_OPRF(secret, 3, 2, it);
  const tOPRFTestLambda = await testT_OPRF(secret, 3, 2, it, true);
  console.timeEnd('\nTotal runtime for tests');
}

/**
 * Tests Schnorr Identification Scheme correctness and performance.
 * @param {int} it Iteration count
 * @return {boolean} true if all tests pass, false otherwise
 */
function testSchnorr(it=5) {
  const G = new PrimeGroup();
  const secret = G.randomExponent();
  for (let i = 1; i <= it; i++) {
    console.time('Schnorr test #' + i);
    const c = schnorrChallenge(G);
    let resp = schnorrResponse(secret, c, G);
    const result =  schnorrVerify(secret[0], secret[1], secret[2], c, G);
    console.timeEnd('Schnorr test #' + i);
    if (result) continue;
    printError('Schnorr test #' + i + ' failed.');
    return false;
  }
  return true;
}

/**
 * Tests the BigInteger library performance.
 * @param {int} it Iteration count
 */
function testBigInt(it=500) {
  // Divide functions into different arrays depending on parameters 
  simpleFunctions = ['bitLen', 'probPrime', 'toString']; // no input functions
  numFunctions = ['add', 'subtract', 'mul', 'divide','eq', 'leq', 'geq', 'lesser', 'greater']; // Not pow, it goes out of range with random numbers
  modFunctions = ['mod', 'randomMod'] // Not invMod, coprime numbers needed
  nmFunctions = ['addMod', 'subtractMod', 'mulMod', 'powMod', 'eqMod']; // num and mod input functions
  lenFunctions =['randomLen', 'randomPrime'];

  let num = BigIntegerAdapter.randomLen(256);
  let mod = BigIntegerAdapter.randomLen(256);
  let len = 256;
  for (const fun of simpleFunctions) {
    const time = timeFunction(fun, [], it);
    print('Testing ' + fun + '...');
    print('\t' + it + ' iterations of ' + fun + ' took ' + time + ' milliseconds.');
    print('\t Average duration of a single run: ' + time/it + ' milliseconds.\n');
  }
  for (const fun of numFunctions) {
    print('Testing ' + fun + '...');
    const time = timeFunction(fun, [num], it);
    print('\t' + it + ' iterations of ' + fun + ' took ' + time + ' milliseconds.');
    print('\t Average duration of a single run: ' + time/it + ' milliseconds.\n');
  }
  for (const fun of modFunctions) {
    print('Testing ' + fun + '...');
    const time = timeFunction(fun, [mod], it);
    print('\t' + it + ' iterations of ' + fun + ' took ' + time + ' milliseconds.');
    print('\t Average duration of a single run: ' + time/it + ' milliseconds.\n');
  }
  for (const fun of nmFunctions) {
    print('Testing ' + fun + '...');
    const time = timeFunction(fun, [num, mod], it);
    print('\t' + it + ' iterations of ' + fun + ' took ' + time + ' milliseconds.');
    print('\t Average duration of a single run: ' + time/it + ' milliseconds.\n');
  }
  for (const fun of lenFunctions) {
    print('Testing ' + fun + '...');
    const time = timeFunction(fun, [len], it);
    print('\t' + it + ' iterations of ' + fun + ' took ' + time + ' milliseconds.');
    print('\t Average duration of a single run: ' + time/it + ' milliseconds.\n');
  }
}

/**
 * Tests a given function's performance.
 * TODO: Open this function to other classes' functions.
 * @param {string} fun Function name
 * @param {array} params Function parameters
 * @param {it} Iteration count
 * @return {int} Total time spent executing the function
 */
function timeFunction(fun, params, it) {
  let t0, t1;
  let total = 0; 
  for (let i = 1; i <= it; i++) {
    let rand = BigIntegerAdapter.randomLen(256);
    if(fun.startsWith('random')) { // Static methods start with 'random'
      t0 = performance.now();
      BigIntegerAdapter[fun](...params);
      t1 = performance.now();
    } else {
      t0 = performance.now();
      rand[fun](...params);
      t1 = performance.now();
    }
    total += t1-t0;
  }
  return total;
}

/**
 * Tests t-OPRF. Randomly generates key.
 * @param {string} secret Client input
 * @param {int} n Share count
 * @param {int} t Threshold
 * @param {int} it Iteration count
 * @param {boolean} lambdas Whether the lambdas are precalculated by servers
 * @return {Promise<boolean>} Whether the tests are successful
 */
async function testT_OPRF(secret, n, t, it, lambdas=false) {
  // TODO: Make sure the time starts on consistent lines
  const G = new PrimeGroup();
  let Hp_x = await hashPrime(secret, G);
  Hp_x = new BigIntegerAdapter(Hp_x, 16);
  console.time('t-OPRF tests with'+
    (lambdas ? '' : 'out')+
    ' lambdas pre-calculated');
  for (let i = 1; i <= it; i++) {
    console.time('t-OPRF test #' + i + ': n=' + n*i + ', t=' + t*i);
    const key = G.randomExponent();
    const result = Hp_x.powMod(key, G.modulus);
    const keys = shamirGenShares(key, n*i, t*i, G).slice(0, t*i);
    if (VERBOSE) { // May help reduce a loop
      printVerbose('Generated key shares:');
      for (const key_i of keys) {
        printVerbose('\tKey #' + key_i[0] + ': ' + key_i[1].toString());
      }
    }
    const [ro, alpha] = await oprfMask(secret, G);
    const betas = [];
    for (let i = 1; i <= keys.length; i++) {
      const key_i = keys[i-1];
      const beta_i = [key_i[0], await oprfChallenge(alpha, key_i[1], G)];
      if (lambdas) beta_i.push(calculateLambda(i, keys.length, G.order));
      betas.push(beta_i);
    }
    const resp = await oprfResponse(betas, ro, G);
    console.timeEnd('t-OPRF test #' + i + ': n=' + n*i + ', t=' + t*i);
    const check = result.eqMod(resp, G.modulus);
    if (check) continue;
    printError('t-OPRFtests failed at n=' + n*i + ', t=' + t*i);
    printError('Result:\n' + result.toString());
    printError('Response:\n' + resp.toString());
    console.timeEnd('t-OPRF tests with'+
      (lambdas ? '' : 'out')+
      ' lambdas pre-calculated');
    return false;
  }
  console.timeEnd('t-OPRF tests with'+
    (lambdas ? '' : 'out')+
    ' lambdas pre-calculated');
  return true;
}

/**
 * Chooses a random key uniform in group exponents and
 * completes an OPRF within itself. How oblivious...
 * @param {string} secret Client input
 * @return {Promise<boolean>} Whether the tests are successful
 */
async function testOPRF(secret) {
  printDebug('Testing OPRF.', color='orange');
  const G = new PrimeGroup();
  console.time('OPRF test');
  let Hp_x = await hashPrime(secret, G);
  Hp_x = new BigIntegerAdapter(Hp_x, 16);
  const key = G.randomExponent();
  const result = Hp_x.powMod(key, G.modulus);
  const [ro, alpha] = await oprfMask(secret, G);
  const beta = await oprfChallenge(alpha, key, G);
  const resp = await oprfResponse(beta, ro, G);
  const check = result.eqMod(resp, G.modulus);

  printVerbose(`key: ${key.toString()} \n`, color='orange');
  printVerbose(`result: ${result.toString()} \n`, color='orange');
  printVerbose(`ro: ${ro.toString()} \n`, color='orange');
  printVerbose(`alpha: ${alpha.toString()} \n`, color='orange');
  printVerbose(`beta: ${beta.toString()} \n`, color='orange');
  printVerbose(`resp: ${resp.toString()} \n`, color='orange');

  console.timeEnd('OPRF test');
  return check;
}

/**
 * Tests Shamir's Secret Sharing on base or exponenets.
 * @param {int} n Share count
 * @param {int} t Threhsold
 * @param {int} it Iteration count
 * @param {boolean} exponent Whether Shamir is done on exponents
 * @return {boolean} Whether the tests are successful
 */
function testShamir(n, t, it, exponent=false) {
  const G = new PrimeGroup();
  const modulus = G.modulus;
  const order = G.order;
  console.time('Shamir tests');
  for (let i = 1; i <= it; i++) {
    console.time('Shamir test on '+
      (exponent ? 'exponent' : 'base')+
      ' #' + i + ': n=' + n*i + ', t=' + t*i);
    const secret = G.randomExponent();
    const shares = shamirGenShares(secret, n*i, t*i, G);
    if (VERBOSE) { // This redundant check may reduce unnecessary loops
      printVerbose('Generated shares:');
      for (const share of shares) {
        printVerbose('\tShare #' + share[0] + ': ' + share[1].toString());
      }
    }
    let secret_elm;
    if (exponent) {
      const elm = G.randomElement();
      secret_elm = elm.powMod(secret, modulus);
      for (const share of shares) {
        share[1] = elm.powMod(share[1], modulus);
      }
    }
    const recons = shamirCombineShares(shares.slice(0, t*i), G, exponent);
    printVerbose('Secret reconstructed:');
    printVerbose('\tOriginal secret: ' + secret.toString());
    printVerbose('\tReconstructed secret: ' + recons.toString());
    console.timeEnd('Shamir test on '+
      (exponent ? 'exponent' : 'base')+
      ' #' + i + ': n=' + n*i + ', t=' + t*i);
    const check = exponent ?
      secret_elm.eqMod(recons, modulus) : secret.eqMod(recons, order);
    if (check) continue;
    printError('Shamir\'s Secret Sharing tests on '+
      (exponent ? 'exponent' : 'base')+
      ' failed at n=' + n*i + ', t=' + t*i);
    printError('Secret:\n' + secret.toString());
    printError('Recons:\n' + recons.toString());
    console.timeEnd('Shamir tests');
    return false;
  }
  console.timeEnd('Shamir tests');
  return true;
}

/**
 * Tests polynomial operations.
 * @param {int} it Iteration count
 * @return {boolean} Whether the tests are successful
 */
function testPolynomials(it) {
  const G = new PrimeGroup();
  console.time('Polynomial tests');
  for (let i = 1; i <= it; i++) {
    console.time('Polynomial test #'+i);
    const a0 = G.randomExponent();
    const pol = genPol(a0, 5*i, G);
    const eval_at_0 = evalPol(pol, 0, G);
    console.timeEnd('Polynomial test #'+i);
    if (a0.eq(eval_at_0)) continue;
    printError('Polynomial test failed.');
    printError('Constant term chosen:\n' + a0.toString());
    printError('Constant term evaluated:\n' + eval_at_0.toString());
    console.timeEnd('Polynomial tests');
    return false;
  }
  console.timeEnd('Polynomial tests');
  return true;
}

/**
 * Tests group operations.
 * @param {int} it Iteration count
 * @return {boolean} Whether the tests are successful
 */
function testGroup(it) {
  const G = new PrimeGroup();
  console.time('Group tests');
  for (let i = 1; i <= it; i++) {
    console.time('Group test #'+i);
    const x = G.randomElement();
    const x_inv = x.invMod(G.modulus);
    const e = x.mulMod(x_inv, G.modulus);
    console.timeEnd('Group test #'+i);
    const check = e == 1;
    if (check) continue;
    printError('Inversion failed. e: ' + e.toString());
    printError('Random x: ' + x.toString());
    printError('Calculated x inverse: ' + x_inv.toString());
    console.timeEnd('Group tests');
    return false;
  }
  console.timeEnd('Group tests');
  return true;
}

// --- Tests end ---


// --- Symmetric Encryption Functions ---
async function decrypt(ciphertext, password, hashFunction, iterations, salt, counter) {
  const dec = new TextDecoder();
  let Crypto;
  if (typeof require !== 'undefined' && require.main === module) {
    Crypto = require('crypto');
  } else {
    Crypto = self.crypto;
  }
  const key = deriveKey(password, hashFunction, iterations, salt);
  const decrypted = await Crypto.subtle.decrypt(
    {
      name: "AES-CTR",
      counter,
      length:64
    },
    key,
    ciphertext);
  return dec.decode(decrypted);
}


/**
 * A wrapper function for Crypto package's encryption to
 * simplify its calling.
 * @param {BigIntegerAdapter} message  Plaintext to be encrypted
 * @param {string} password Taken from user to derive the encryption key
 * @param {int} iterations PBKDF2 iteration count
 * @param {int} saltLen PBKDF2 salt length
 * @returns {[ArrayBuffer, Uint8Array(16), Uint8Array(saltLen)]} [ciphertext, counter, salt]
 */
async function encrypt(message, password, hashFunction, iterations, saltLen) {
  //TODO: Safety check for inputs
  let Crypto;
  if (typeof require !== 'undefined' && require.main === module) {
    Crypto = require('crypto');
  } else {
    Crypto = self.crypto;
  }
  const plaintext = enc.encode(message.toString(16));
  const salt = Crypto.getRandomValues(new Uint8Array(saltLen));
  const key  = await deriveKey(password, hashFunction, iterations, salt);
  let counter = Crypto.getRandomValues(new Uint8Array(16));
  let ciphertext = await Crypto.subtle.encrypt(
    {
      name: "AES-CTR",
      counter,
      length: 64
    },
    key,
    plaintext);
  return [ciphertext, counter, salt];
}

async function deriveKey(password, hashFunction, iterations, salt) {
  const enc = new TextEncoder();
  let Crypto;
  if (typeof require !== 'undefined' && require.main === module) {
    Crypto = require('crypto');
  } else {
    Crypto = self.crypto;
  }
  const keyMaterial = await Crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]);
  
  const key = await Crypto.subtle.deriveKey(
    {
      "name": "PBKDF2",
      salt: salt,
      "iterations": iterations,
      "hash": hashFunction
    },
    keyMaterial,
    {"name": "AES-CTR", "length": 256},
    true,
    ["encrypt", "decrypt"]);
  return key;
}

async function exportKey(key) {
  return await Crypto.subtle.exportKey("raw", key);
}

async function importKey(exportedKey) {
  return await Crypto.subtle.importKey(
   "raw",
    exportedKey,
    "AES-CTR",
    true,
    ["encrypt", "decrypt"]);
}
/// --- Symmetric Encryption end ---

// --- Identification Scheme Functions ---
// Schnorr scheme according to: https://asecuritysite.com/encryption/schnorr
// I used the same notation for the variables for clarity.

/**
 * Generates a random exponent from the common PrimeGroup to be used as challenge.
 * @param {PrimeGroup} group Common PrimeGroup
 * @return {BigIntegerAdapter} c Random challenge
 */
function schnorrChallenge(group) {
  const c = group.randomExponent();
  return c;
}

/**
 * ! Note: public key is calculated here.
 * Generates a responds to the challenge, proving knowledge of x.
 * Note that X = g^x is normally assumed to be known, because the
 * public key is (g^x, group). For the sake of simplicity, it is
 * returned here; as this has little effect on performance numbers.
 * @param {BigIntegerAdapter} x The secret value to be proven, an
 *  exponent in the group
 * @param {BigIntegerAdapter} c The challenge sent by the challenger
 * @param {PrimeGroup} group Common PrimeGroup
 * @return {[BigIntegerAdapter, BigIntegerAdapter, BigIntegerAdapter]} [X Y z]
 *  X = g^x the public key, Y = g^random and z = y*x^c the response.
 */
function schnorrResponse(x, c, group) {
  const mod = group.modulus;
  const g = group.generator;
  const X = g.powMod(x, mod);
  const y = group.randomExponent();
  const Y = g.powMod(y, mod);
  const z = y.mulMod(x.powMod(c, mod), mod);
  return [X, Y, z];
}

/**
 * Verifies that the prover has the private key corresponding to the public key X.
 * @param {BigIntegerAdapter} X The public key
 * @param {BigIntegerAdapter} Y First part of the response
 * @param {BigIntegerAdapter} z Second part of the response
 * @param {BigIntegerAdapter} c The challenge
 * @param {PrimeGroup} group Common PrimeGroup
 * @return {boolean} g^z == Y*X^c (in group)
 */
function schnorrVerify(X, Y, z, c, group) {
  const mod = group.modulus;
  const g = group.generator;
  const val1 = g.powMod(z, mod);
  const val2 = Y.mulMod(X.powMod(c, mod), mod);
  return val1.eqMod(val2, mod);
}

// --- Identification Scheme end ---

// --- Secret Sharing functions ---
// TODO: Get the PrimeGroup comments into consistency
/**
 * Generates shares from a secret according to Compartmanted
 * Secret Sharing as presented in INSERT LINK HERE
 * Each compartment (bucket) has a threshold of its own,
 * allowing for an access control mechanism.
 * @param {BigIntegerAdapter} secret Secret to divide into shares
 * @param {[int]} bucketSizes Sizes of each compartment
 * @param {[int]} bucketThresholds Thresholds of each compartment
 * @param {PrimeGroup} group The group in which the operations are done
 * @return {[[(int, BigIntegerAdapter)]]} Each element corresponds to the shares
 * of compartment i. Element j of compartment i should get the share
 * shares[i][j].
 */
function compartmantedGenShares(secret, bucketSizes, bucketThresholds, group) {
  if (bucketSizes.length != bucketThresholds.length) {
    printError('bucketSizes and bucketThresholds sizes do not match.');
    return [];
  }
  const bucketCount = bucketSizes.length;
  const bucketSecrets = [];
  let total = new BigIntegerAdapter(0);
  for (let i = 1; i < bucketCount; i++) {
    const randomElement = group.randomElement();
    total.addMod(randomElement, group.modulus);
    bucketSecrets.push(randomElement);
  }
  bucketSecrets.push(secret.subtractMod(total, group.modulus)); // Sum of bucketSecrets = secret
  const shares = [];
  for (let i = 0; i < bucketCount; i++) {
    shares.push[shamirGenShares(bucketSecrets[i], bucketSizes[i], bucketThresholds[i], group)];
  }
  return shares;
}

/**
 * TODO: Pre-calculation of lambdas
 * TODO: Calculation in the exponent
 * Combines shares to reveal a secret according to Compartmanted
 * Secret Sharing as presented in INSERT LINK HERE.
 * Does not check for the correctness of shares. If the shares
 * are input incorrectly, generates a wrong output.
 * @param {[[(int, BigIntegerAdapter)]]} shares An array, i^th element of whose
 * consists of the shares of comparmartment i.
 * @param {PrimeGroup} group The group in which the operations are done 
 * @returns {BigIntegerAdapter} The reconstructed secret
 */
function compartmantedCombineShares(shares, group) {
  const bucketCount = shares.length;
  var secret = new BigIntegerAdapter(0);
  for (let i = 0; i < bucketCount; i++) {
    const bucketSecret = shamirCombineShares(shares[i], group);
    secret = secret.addMod(bucketSecret, group.modulus);
  }
  return secret;
}

/**
 * Takes an array of indices and shares where the elements
 * are in the form [k, share #k]. Uses Lagrange interpolation
 * to combine the shares and returns the secret as a BigInteger.
 * * Does not check for n, t values! If not enough shares are
 * * given, simply returns a wrong value. Giving more than enough
 * * shares does not change the output.
 * Pass lambdas as the third elements of shares if they are
 * precomputed, i.e., shares[i] = [x_i, y_i, lambda_i]. Otherwise
 * pass each share as tuples, i.e., shares[i] = [x_i, y_i].
 *
 * @param {[(int, BigIntegerAdapter)]} shares: A vector of shares 
 * where each share is of the form [int, BigIntegerAdapter, BigIntegerAdapter?],
 * corresponding to [shareIndex, shareValue, shareLambda]. shareLambda
 * is only input when lambdas are pre-calculated.
 * @param {PrimeGroup} group: A PrimeGroup object determining the
 * modulus of operations
 * @param {boolean} exponent: A boolean determining whether the
 * interpolation will be done on the exponents
 * @return {BigIntegerAdapter} The reconstructed secret
 */
function shamirCombineShares(shares, group, exponent=false) {
  const n = shares.length;
  const mod = group.modulus;
  const ord = group.order;
  let at_0 = exponent ? new BigIntegerAdapter(1) : new BigIntegerAdapter(0);
  const lambdas = shares.length == 3;
  for (const point of shares) {
    const i = point[0]; // int, not bigInt
    const at_i = point[1];
    const lambda_i = lambdas ? point[2] : calculateLambda(i, n, ord);
    if (exponent) at_0 = at_0.mulMod(at_i.powMod(lambda_i, mod), mod);
    else at_0 = at_0.addMod(at_i.mulMod(lambda_i, ord), ord);
  }
  return at_0;
}

/**
 * Generate shares from a secret according to Shamir's Secret Sharing
 * @param {string | BigIntegerAdapter} secret Secret to divide into shares
 * @param {int} n Share count
 * @param {int} t Threhsold
 * @param {PrimeGroup} group A PrimeGroup object determining the
 * modulus of operations
 * @return {[(int, BigIntegerAdapter)]} The shares that uniquely determine the
 * secret. Each share is a tuple of (int, BigIntegerAdapter)
 */
function shamirGenShares(secret, n, t, group) {
  if (typeof secret == 'string') {
    secret = new BigIntegerAdapter(secret);
  }
  const pnomial = genPol(secret, t, group);
  const shares = [];
  for (let i = 1; i <= n; i++) {
    shares.push([i, evalPol(pnomial, i, group)]);
  }
  return shares;
}

/**
 * Calculates the Lagrange interpolation coefficient for x = i and x_0 = 0.
 * @param {int} i Point x
 * @param {int} n Share number
 * @param {BigIntegerAdapter} order Modulus of operations
 * @return {int} Lagrange Interpolation Coefficient Lambda_i
 */
function calculateLambda(i, n, order) {
  lambda_i = new BigIntegerAdapter(1);
  for (let j = 1; j <= n; j++) {
    if (i == j) continue;
    const inv = (new BigIntegerAdapter(j-i)).invMod(order); // 1/j-i
    const temp = inv.mulMod(j, order); // j/j-i
    lambda_i = lambda_i.mulMod(temp, order);
  }
  return lambda_i;
}

/**
 * Constructs a degree t-1 semi-random polynomial.
 * All coefficients are BigIntegerAdapter objects.
 * @param {BigIntegerAdapter} secret Secret to divide into shares
 * @param {int} t Threhsold
 * @param {PrimeGroup} group A PrimeGroup object determining the
 * modulus of operations
 * @return {[BigIntegerAdapter]} An array of polynomial coefficients,
 * representing a polynomial of degree t-1 with a_0 = secret,
 * a_i = random for all 0<i<t.
 */
function genPol(secret, t, group) {
  const pnomial = [secret];
  for (let i = 1; i < t; i++) {
    const rand = group.randomExponent();
    pnomial.push(rand);
  }
  return pnomial;
}

/**
 * Evaluates a polynomial at a point in a group.
 * @param {[BigIntegerAdapter]} pol An array representing a polynomial
 * @param {int} x A point on which to evaluate the polynomial
 * @param {PrimeGroup} group A PrimeGroup object determining the
 * modulus of operations
 * @return {BigIntegerAdapter} The polynomial evaluated at x
 */
function evalPol(pol, x, group) {
  x = new BigIntegerAdapter(x);
  const mod = group.order;
  let sum = new BigIntegerAdapter(0);
  for (let i = 0; i < pol.length; i++) {
    const x_i = pol[i].mulMod(x.powMod(i, mod), mod);
    sum = sum.addMod(x_i, mod);
  }
  return sum;
}
// --- Secret Sharing end ---

// --- OPRF functions ---

/**
 * Calculates beta^(ro^-1) = alpha^(k*(ro^-1)) = Hp_x^(ro*k*(ro^-1)) = Hp_x^k
 * If using t-OPRF, pass betas as an array. Otherwise pass a BigIntegerAdapter.
 * @param {[BigIntegerAdapter] | BigIntegerAdapter} betas Either beta (on OPRF)
 * or an array of betas (on t-OPRF).
 * @param {BigIntegerAdapter} ro The random number previously calculated
 * using oprfMask()
 * @param {PrimeGroup} group A PrimeGroup object determining the
 * modulus of operations
 * @return {Promise<BigIntegerAdapter>} The output of OPRF: Hp_x^k
 */
async function oprfResponse(betas, ro, group) {
  const threshold = !(betas instanceof BigIntegerAdapter);
  const lambdas = threshold && betas[0].length == 3;
  // betas is actually a single beta in the below case
  if (!threshold) return betas.powMod(ro.invMod(group.order), group.modulus);
  const shares = [];
  for (const beta of betas) {
    const index = beta[0];
    const toRoInv = await oprfResponse(beta[1], ro, group);
    const share = [index, toRoInv];
    if (lambdas) share.push(betas[2]);
    shares.push(share);
  }
  return shamirCombineShares(shares, group, true);
}

/**
 * Generates the challenge alpha^k.
 * @param {BigIntegerAdapter} alpha Hp_x^ro received from client
 * @param {BigIntegerAdapter} k The OPRF key, secret value
 * @param {PrimeGroup} group A PrimeGroup object determining the
 * modulus of operations
 * @return {Promise<BigIntegerAdapter>} beta = alpha^k
 */
async function oprfChallenge(alpha, k, group) {
  return alpha.powMod(k, group.modulus);
}

/**
 * Creates the masked text to be sent to each SP.
 * Call this function once, and send alpha to each SP.
 * This returns a promise resolving to [ro, alpha], the SPs will responds with
 * beta_i = alpha^k_i and will also send c_i
 * This function also returns ro, which should be kept secret and only
 * be used as an input to the reconstructPassword function.
 * @param {string} secret Client input to OPRF
 * @param {PrimeGroup} group A PrimeGroup object determining the
 * modulus of operations
 * @return {Promise<[BigIntegerAdapter, BigIntegerAdapter]>} [ro, alpha]
 * A pair holding the random number ro and alpha= Hp_x^ro
 */
async function oprfMask(secret, group) {
  const ro = group.randomElement();
  const Hp_x = await hashPrime(secret, group);
  printVerbose('Hp_x: ' + Hp_x);
  let Hp_xToRo = new BigIntegerAdapter(Hp_x, 16);
  Hp_xToRo = Hp_xToRo.powMod(ro, group.modulus);
  return [ro, Hp_xToRo];
}
// --- OPRF end ---

// --- Hash functions ---
/**
 * Hashes a string to an element in the given group.
 * Returns a promise resolving to the hash as a hex string.
 * This is not fixed sized output, though.
 * @param {string} str String to digest into hash
 * @param {PrimeGroup} group A PrimeGroup object determining the
 * modulus of operations
 * @return {Promise<string>} Hp(str) in hexadecimal string form
 */
async function hashPrime(str, group) { //* Full domain hash, problem: Z_n*
  const g = group.generator;
  const mod = group.modulus;
  let baseHash = await hash(str); // Hex string
  baseHash = new BigIntegerAdapter(baseHash, 16);
  baseHash = baseHash.mod(group.order); // bigInt
  let hp = g.powMod(baseHash, mod); // bigInt
  hp = hp.toString(16); // Hex string
  return hp;
}

/**
 * Hashes a string using SHA-256, returns a promise resolving
 * to the hash as a string.
 * @param {string} str String to digest into hash
 * @return {Promise<string>} SHA256(str) in hexadecimal string form
 */
async function hash(str) {
  const enc = new TextEncoder();
  const data = enc.encode(str);
  let Crypto;
  if (typeof require !== 'undefined' && require.main === module) {
    Crypto = require('crypto');
  } else {
    Crypto = self.crypto;
  }
  let hash = await Crypto.subtle.digest('SHA-256', data);
  hash = Buffer.from(hash).toString('hex');
  // Converstion to string may reduce size only when there
  //  are 0s on the left side
  while (hp.length < 32) hp = '0' + hp;
  return hash;
}
// --- Hash end ---

// --- Classes ---
/**
 * A PrimeGroup class representing a group of prime order
 * and prime modulus. Generates a random prime modulus and
 * prime order of given bit lengths, and sets a generator.
 */
class PrimeGroup {
  /**
   * @param {BigIntegerAdapter} modLen
   * @para'\t' + m {BigIntegerAdapter} oLen
   * @param {BigIntegerAdapter} stat
   * @throws {RangeError} If the generated primes do not satisfy
   * given bit length conditions. If this is thrown, there is
   * a bug with prime generation, so this should never happen
   * under normal circumstances.
   */
  constructor(modLen, oLen, stat) {
    // Check preconditions
    if (modLen < 512) {
      printError('Tried to create a group with modulus length < 512');
      modLen = 512;
    }
    if (oLen < 160) {
      printError('Tried to create a group with order length < 160');
      oLen = 160;
    }
    if (oLen < 2*stat) {
      printError('Tried to create a group with order length < 2*stat');
      oLen = 2*stat;
    }
    this.stat = stat;
    // Decide an order
    this.order = BigIntegerAdapter.randomPrime(oLen, stat);

    if (this.order.bitLen() != oLen) {
      throw new RangeError('Prime Order does not satisfy'+
        'necessary bit length.', {
        cause: {code: 'BitLength', values: [this.order]},
      });
    }

    // Find a prime modulus
    const factLen = modLen - oLen;
    let factor, modulus;
    do {
      const t0 = performance.now()
      factor = BigIntegerAdapter.randomLen(factLen, true);
      modulus = this.order.times(factor).add(1);
      const t1 = performance.now()
      print(t1-t0 + ' ms');
    } while (modulus.bitLen() != modLen || !modulus.probPrime(this.stat));
    this.modulus = modulus;
    if (this.modulus.bitLen() != modLen) {
      throw new RangeError('Prime Modulus does not satisfy'+
        'necessary bit length.', {
        cause: {code: 'BitLength', values: [this.modulus]},
      });
    }

    // Come up with a generator
    let gen = new BigIntegerAdapter(1);
    while (gen.eq(1)) {
      const gammaPrime = BigIntegerAdapter.randomMod(this.modulus);
      gen = gammaPrime.powMod(factor, this.modulus);
    }
    this.generator = gen;
  }

  /**
   * Returns a random BigIntegerAdapter element.
   */
  randomElement() {
    return this.generator.powMod(BigIntegerAdapter.randomMod(this.order), this.modulus);
  }
}

/**
 * A class employing Adapter pattern for increasing modularity of the
 * code by reducing the dependency factor of BigInteger libraries to
 * a single origin.
 */
class BigIntegerAdapter {
  /**
   * @param {BigIntegerAdapter | int | string} value The value to be
   * encapsulated
   * @param {int} radix The format of input value
   */
  constructor(value, radix=10) {
    this.bigInt = require('big-integer');
    if (value instanceof BigIntegerAdapter) this.value = value.value;
    else this.value = this.bigInt(value, radix);
  }
  // Base calls

  /**
   * Performs addition.
   * @param {int | BigIntegerAdapter} num Number to add
   * @return {BigIntegerAdapter} value + num
   */
  add(num) {
    if (Number.isInteger(num)) num = new BigIntegerAdapter(num);
    return new BigIntegerAdapter(this.value.add(num.value));
  }
  /**
   * Performs subtraction.
   * @param {int | BigIntegerAdapter} num Number to subtract
   * @return {BigIntegerAdapter} value - num
   */
  subtract(num) {
    if (Number.isInteger(num)) num = new BigIntegerAdapter(num);
    return new BigIntegerAdapter(this.value.subtract(num.value));
  }
  /**
   * Performs multiplication.
   * @param {int | BigIntegerAdapter} num Number to multiply
   * @return {BigIntegerAdapter} value * num
   */
  mul(num) {
    if (Number.isInteger(num)) num = new BigIntegerAdapter(num);
    return new BigIntegerAdapter(this.value.times(num.value));
  }
  /**
   * Synonim for mul(num)
   * @param {int | BigIntegerAdapter} num Number to multiply
   * @return {BigIntegerAdapter} value * num
   */
  times(num) {
    return this.mul(num);
  }
  /**
   * Performs division.
   * @param {int | BigIntegerAdapter} num Number to divide to
   * @return {BigIntegerAdapter} value / num
   */
  divide(num) {
    if (Number.isInteger(num)) num = new BigIntegerAdapter(num);
    return new BigIntegerAdapter(this.value.divide(num.value));
  }
  /**
   * Performs exponentiation.
   * @param {int | BigIntegerAdapter} num Number to use as exponent
   * @return {BigIntegerAdapter} value ^ num
   */
  pow(num) {
    if (Number.isInteger(num)) num = new BigIntegerAdapter(num);
    return new BigIntegerAdapter(this.value.pow(num.value));
  }
  /**
   * Checks whether a given number is equal to value.
   * @param {int | BigIntegerAdapter} num A number
   * @return {boolean} value == num
   */
  eq(num) {
    if (Number.isInteger(num)) num = new BigIntegerAdapter(num);
    return this.value.eq(num.value);
  }
  /**
   * Checks whether a given number is lesser or equal to value.
   * @param {int | BigIntegerAdapter} num A number
   * @return {boolean} value <= num
   */
  leq(num) {
    if (Number.isInteger(num)) num = new BigIntegerAdapter(num);
    return this.value.leq(num.value);
  }
  /**
   * Checks whether a given number is greater than or equal to value.
   * @param {int | BigIntegerAdapter} num A number
   * @return {boolean} value >= num
   */
  geq(num) {
    if (Number.isInteger(num)) num = new BigIntegerAdapter(num);
    return this.value.geq(num.value);
  }
  /**
   * Checks whether a given number is lesser than value.
   * @param {int | BigIntegerAdapter} num A number
   * @return {boolean} value < num
   */
  lesser(num) {
    if (Number.isInteger(num)) num = new BigIntegerAdapter(num);
    return this.value.lesser(num.value);
  }
  /**
   * Checks whether a given number is greater than value.
   * @param {int | BigIntegerAdapter} num A number
   * @return {boolean} value > num
   */
  greater(num) {
    if (Number.isInteger(num)) num = new BigIntegerAdapter(num);
    return this.value.greater(num.value);
  }
  // Mod calls always return positive

  /**
   * Performs modulo operation. Always return positive remainder.
   * @param {int | BigIntegerAdapter} mod Modulus
   * @return {BigIntegerAdapter} Remainder of mod/value
   */
  mod(mod) {
    if (Number.isInteger(mod)) mod = new BigIntegerAdapter(mod);
    const result = new BigIntegerAdapter(this.value.mod(mod.value));
    return result.lesser(0) ? result.add(mod) : result;
  }
  /**
   * Performs modular addition.
   * @param {int | BigIntegerAdapter} num Number to add
   * @param {int | BigIntegerAdapter} mod Modulus
   * @return {BigIntegerAdapter} value + num (mod mod)
   */
  addMod(num, mod) {
    return this.add(num).mod(mod);
  }
  /**
   * Performs modular subtraction. Always returns a positive number.
   * @param {int | BigIntegerAdapter} num Number to subtract
   * @param {int | BigIntegerAdapter} mod Modulus
   * @return {BigIntegerAdapter} value - num (mod mod)
   */
  subtractMod(num, mod) {
    return this.subtract(num).mod(mod);
  }
  /**
   * Performs modular multiplicaiton.
   * @param {int | BigIntegerAdapter} num Number to multiply
   * @param {int | BigIntegerAdapter} mod Modulus
   * @return {BigIntegerAdapter} value * num (mod mod)
   */
  mulMod(num, mod) {
    return this.mul(num).mod(mod);
  }
  /**
   * Performs modular exponentiation.
   * @param {int | BigIntegerAdapter} num Number to use as exponent
   * @param {int | BigIntegerAdapter} mod Modulus
   * @return {BigIntegerAdapter} value ^ num (mod mod)
   */
  powMod(num, mod) {
    if (Number.isInteger(num)) num = new BigIntegerAdapter(num);
    if (Number.isInteger(mod)) mod = new BigIntegerAdapter(mod);
    return new BigIntegerAdapter(this.value.modPow(num.value, mod.value));
  }
  /**
   * Checks wheter a given number is congruent to value in modulus mod
   * @param {int | BigIntegerAdapter} num A number
   * @param {int | BigIntegerAdapter} mod Modulus
   * @return {boolean} value == num (mod mod)
   */
  eqMod(num, mod) {
    if (Number.isInteger(num)) num = new BigIntegerAdapter(num);
    if (Number.isInteger(mod)) mod = new BigIntegerAdapter(mod);
    const value = this.mod(mod);
    num = num.mod(mod);
    return value.eq(num);
  }
  /**
   * Returns the inverse of value in modulus mod
   * @param {int | BigIntegerAdapter} mod Modulus
   * @return {BigIntegerAdapter} Inverse of value, i.e., a number
   * x such that x*value == 1 (mod mod)
   */
  invMod(mod) {
    if (Number.isInteger(mod)) mod = new BigIntegerAdapter(mod);
    return new BigIntegerAdapter(this.value.modInv(mod.value));
  }

  // Other functionalities

  /**
   * Generates a random number of at most given bit length.
   * Note that the returned number might have smaller
   * bit length if the most significant bits are 0.
   * Use the force parameter to assure that the bit
   * length is exactly as given.
   * Note that force=true implies len-1 bits of randomness.
   * @param {int} len Bit size of random number
   * @param {bool} force Forces the first bit to be 1.
   * @return {BigIntegerAdapter} rnd in {0, 1}^len
   */
  static randomLen(len, force=false) {
    // * No modulo operations, no biasing.
    // Decide on Crypto interface
    let Crypto;
    if (typeof require !== 'undefined' && require.main === module) {
      Crypto = require('crypto');
    } else {
      Crypto = self.crypto;
    }
    // Create a random ArrayBuffer
    const upLen = Math.ceil(len/8);
    let rnd = Crypto.getRandomValues(new Uint8Array(upLen)); // Uint8Array
    // Remove unneeded bits
    const necessaryBits = 8 - (upLen*8 - len);
    rnd[0] = rnd[0] & parseInt('1'.repeat(necessaryBits), 2);
    if (force) rnd[0] = rnd[0] | parseInt('1'+'0'.repeat(necessaryBits-1), 2);
    // Transform to BigIntegerAdapter
    rnd = Buffer.from(rnd).toString('hex'); // Hex
    return new BigIntegerAdapter(rnd, 16);
  }

  /**
   * Generates a random number between 0 and mod-1.
   * @param {int | BigIntegerAdapter} mod Upper bound
   * @return {BigIntegerAdapter} 0 <= rnd < mod
   */
  static randomMod(mod) {
    // ! Careful, biasing unhandled!
    return BigIntegerAdapter.randomLen(mod.bitLen()).mod(mod);
  }

  /**
   * Generates a random probable prime of desired bit-length.
   * @param {int} len The number of digits in the binary
   * representation of the generated prime.
   * @param {int} iterations The iterations for probable
   * prime testing.
   * @return {BigIntegerAdapter} A random probable prime
   */
  static randomPrime(len, iterations=5) {
    printDebug('Generating a random prime of length ' + len + '.');
    let rand;
    do {
      rand = BigIntegerAdapter.randomLen(len, true);
    } while (!rand.probPrime(iterations));
    printDebug('Prime generated.');
    return rand;
  }

  /**
   * Returns the number of digits required to represent
   * value in binary.
   * @return {int} Bit length of value
   */
  bitLen() {
    return this.value.bitLength();
  }

  /**
   * Returns true if value is very likely to be prime,
   * false otherwise. Always returns true if value is
   * prime, but may also return true if value is composite,
   * with 4^-iterations chance.
   * @param {int} iterations Test count
   * @return {boolean} Whether value is prime
   */
  probPrime(iterations=5) {
    // ! This uses Math.random, which is insecure.
    return this.value.isProbablePrime(iterations);
  }

  /**
   * Creates a string representation of the encapsulated value in given radix.
   * @param {int} radix The base to use to represent the number
   * @return {string} A string representation of the encapsulated value
   */
  toString(radix=5) {
     return this.value.toString(radix);
  }
}

// --- Classes end ---

// --- Some helpful functions ---
function importCrypto() {
  // TODO: Test if this works
  let Crypto;
  if (typeof require !== 'undefined' && require.main === module) {
    Crypto = require('crypto');
  } else {
    Crypto = self.crypto;
  }
  return Crypto;
}


/**
 * Transforms a Buffer into BufferArray.
 * @param {Buffer} buf A Buffer holding any data
 * @return {BufferArray} A BufferArray holding the same data as buf
 */
function toArrayBuffer(buf) {
  const ab = new ArrayBuffer(buf.length);
  const view = new Uint8Array(ab);
  for (let i = 0; i < buf.length; i++) {
    view[i] = buf[i];
  }
  return ab;
}

/**
 * A shorthand function for printing to the console or the process.
 * The coloring currently is bugged, use the special functions below instead.
 * @param {*} T A printable value
 * @param {boolean?} newline Whether to put a newline after. Default is true.
 * @param {boolean?} html Whether the printing is done on html or console.
 * Default is false.
 * @param {string?} color The color of the pring. Default is empty, which
 * prints a black string.
 */
function print(T='', newline=true, html=false, color='') {
  // TODO: Fix this
  // ! Printing with color does not work
  // ! JS and default arguments act unlike Python.
  if (color!='') {
    console.log('%c' + T, 'color: ' + color);
  } else if (!newline) {
    process.stdout.write(T);
  } else if (html) {
    document.write(T);
  } else {
    console.log(T);
  }
}

/**
 * Prints a Debug message in accordance to the global variable
 * DEBUG. Colors the message Orange.
 * @param {*} T A printable value
 */
function printDebug(T) {
  if (DEBUG) console.log('%c' + T, 'color: orange');
}
/**
 * Prints a Verbose message in accordance to the global variable
 * VERBOSE. Colors the message Magenta.
 * @param {*} T A printable value
 */
function printVerbose(T) {
  if (VERBOSE) console.log('%c' + T, 'color: magenta');
}
/**
 * Prints an error message. Colors the message Red.
 * @param {*} T A printable value
 */
function printError(T) {
  console.log('%c' + T, 'color: red');
}

// --- Helpful functions end ---

// This check protects importing scripts from running main().
if (typeof require != 'undefined' && require.main == module) {
  manuelTest();
}
