/* eslint-disable camelcase */
// ! Keep DEBUG and VERBOSE false for release. They print out secret values.
const DEBUG = false;
const VERBOSE = false;
const FOLDER_PATH = 'BrowserCryptoLib'
// TODO: Standardize Debug and Verbose printing (Debug starting, ending. Verbose values.)
// TODO: Remove redundant if(VERBOSE) checks.
// --- TESTS ---
// eslint-disable-next-line require-jsdoc

async function main() {
  // This function is run by Node.
  const times = await testAll(50);
  const filename = FOLDER_PATH + '/raw results.csv';
  const append = false;
  if(exportToCSV(times, filename, append))
    print('Results ' + (append ? 'appended' : 'recorded') + ` to ${filename}.`);
  else
    print('Error exporting to CSV.');
}

async function testAll(it) {
  /**
   * All tests should be configured here. Below are some example calls.
   * Test functions return a hashmap of test results, and if a map is
   * passed as a last argument, they append to that map as well. 
   */
  const times = await testSignature(it); // Do not pass a map on the first test call
  await testEncryption(it, times); // Pass the return value of the first call ...
  testSchnorr(it, times); // ... on all of the next test calls.
  await testOPRF(it, times);
  await testTOPRF(11, 6, it, false, times);
  await testTOPRF(13, 7, it, true, times);
  testCompartmented([5, 3, 5, 4], [3, 2, 4, 4], it, times);
  testShamir(11, 6, it, false, false, times);
  testShamir(11, 6, it, false, true, times);
  testShamir(11, 6, it, true, false, times);
  testShamir(11, 6, it, true, true, times);
  return times; // This holds the times of all the calls above.
}

/**
 * All test functions aside from testBigInt, testGroup, and testPolynomials 
 * below test a part of the library and record times in a hashmap, passed as
 * a last optional parameter. If no hashmap is passed, they work on a new one.
 * 'it' determines iteration count. The 3 exceptions are for debug purposes.
 */

async function testSignature(it=5, resultMap) {
  const times = new Map([
    ['Signature KeyGen', []],
    ['Sign', []],
    ['Verify', []]
  ]);
  const message = 'This is some very secret message '+
    'sent over a secure channel.';
  for (let i = 0; i < it; i++ ) {
	  var t0 = performance.now();
	  const keyPair = await generateSignatureKeys();
	  var t1 = performance.now();
	  const keyGenTime = (t1 - t0);
	  t0 = performance.now();
    const signature = await sign(message, keyPair.privateKey);
	  t1 = performance.now();
	  const signTime = (t1 - t0);
    printVerbose('Signature:')
    printVerbose(signature);
	  t0 = performance.now();
    const check = await verify(message, signature, keyPair.publicKey);
	  t1 = performance.now();
	  const verifyTime = (t1 - t0);
    times.get('Signature KeyGen').push(keyGenTime);
    times.get('Sign').push(signTime);
    times.get('Verify').push(verifyTime);
    if (check) continue;
    printError('Signature test #' + i + 'failed.');
		return false;
  }
  print('Signature tests successful.');
  if (!resultMap)
    return times;
  for (const [key, value] of times) {
    resultMap.set(key, value);
  }
  return resultMap;
}

async function testEncryption(it=5, resultMap) {
  const times = new Map([
    ['Encrypt', []],
    ['Decrypt', []]
  ]);
  for (let i = 1; i <= it; i++) {
    const plaintext = BigIntegerAdapter.randomLen(256);
    const password = 'A secure password'
    const hashFunction = 'SHA-256';
    const pbkdfIterations = 100000;
    var t0 = performance.now();
    const [ciphertext, counter, salt] = await encrypt(plaintext,
      password, hashFunction, pbkdfIterations, 5);
    var t1 = performance.now();
    const encryptTime = (t1 - t0);
    t0 = performance.now();
    const decrypted = await decrypt(ciphertext, password,
      hashFunction, pbkdfIterations, salt, counter);
    t1 = performance.now();
    const decryptTime = (t1 - t0);
    times.get('Encrypt').push(encryptTime);
    times.get('Decrypt').push(decryptTime);
    if (decrypted == plaintext.toString(16))
      continue
    printError('Decryption test #' + i +' failed.');
    printDebug('Plaintext: ');
    printDebug(plaintext.toString(16));
    printDebug('Ciphertext: ');
    printDebug(ciphertext.toString(16));
    printDebug('Decrypted: ');
    printDebug(decrypted);
    return false;
  }
  print('Encryption tests successful.');
  if (!resultMap)
    return times;
  for (const [key, value] of times) {
    resultMap.set(key, value);
  }
  return resultMap;
}

function testSchnorr(it=5, resultMap) {
  const times = new Map([
    ['Schnorr Challenge', []],
    ['Schnorr Response', []],
    ['Schnorr Verify', []]
  ]);
  const G = new PrimeGroup();
  const secret = G.randomExponent();
  for (let i = 1; i <= it; i++) {
    var t0 = performance.now();
    const c = schnorrChallenge(G);
    var t1 = performance.now();
    const challengeTime = (t1 - t0);
    t0 = performance.now();
    const resp = schnorrResponse(secret, c, G);
    t1 = performance.now();
    const responseTime = (t1 - t0);
    t0 = performance.now();
    const result =  schnorrVerify(resp[0], resp[1], resp[2], c, G);
    t1 = performance.now();
    const verifyTime = (t1 - t0);
    times.get('Schnorr Challenge').push(challengeTime);
    times.get('Schnorr Response').push(responseTime);
    times.get('Schnorr Verify').push(verifyTime);
    if (result) continue;
    printError('Schnorr test #' + i + ' failed.');
    return false;
  }
  print('Schnorr tests successful.');
  if (!resultMap)
    return times;
  for (const [key, value] of times) {
    resultMap.set(key, value);
  }
  return resultMap;
}


/**
 * Tests a given function's performance. Tested only on BigInt calls.
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
 * Tests t-OPRF. Randomly generates the key.
 * @param {int} n Share count
 * @param {int} t Threshold
 * @param {int} it Iteration count
 * @param {boolean} lambdas Whether the lambdas are precalculated by servers
 * @return {Promise<boolean>} Whether the tests are successful
 */
async function testTOPRF(n, t, it, lambdas=false, resultMap) {
  const messageTrail = `(${n}, ${t}, ${lambdas})`;
  const times = new Map([
    ['t-OPRF Mask ' + messageTrail, []],
    ['t-OPRF Challenge Total ' + messageTrail, []],
    ['t-OPRF Response ' + messageTrail, []]
  ]);
  const G = new PrimeGroup();
  const secret = 'This is some very secret message '+
      'sent over a secure channel.';
  let Hp_x = await groupHash(secret, G);
  Hp_x = new BigIntegerAdapter(Hp_x, 16);
  for (let i = 1; i <= it; i++) {
    const key = G.randomExponent();
    const result = Hp_x.powMod(key, G.modulus);
    const keys = shamirGenShares(key, n, t, G).slice(0, t);
    if (VERBOSE) { // May help reduce a loop
      printVerbose('Generated key shares:');
      for (const key_i of keys) {
        printVerbose('\tKey #' + key_i[0] + ': ' + key_i[1].toString());
      }
    }
    var t0 = performance.now();
    const [rho, alpha] = await oprfMask(secret, G);
    var t1 = performance.now();
    const maskTime = (t1 - t0);
    const betas = [];
    var challengeTime = 0;
    for (const key of keys) {
      t0 = performance.now();
      const beta_i = [key[0], await oprfChallenge(alpha, key[1], G)];
      t1 = performance.now();
      challengeTime += (t1 - t0);
      if (lambdas) beta_i.push(calculateLambda(beta_i[0], keys.length, G.order));
      betas.push(beta_i)
    }
    t0 = performance.now();
    const resp = await oprfResponse(betas, rho, G);
    t1 = performance.now();
    const responseTime = (t1 - t0);
    const check = result.eqMod(resp, G.modulus);
    times.get('t-OPRF Mask ' + messageTrail).push(maskTime);
    times.get('t-OPRF Challenge Total ' + messageTrail).push(challengeTime);
    times.get('t-OPRF Response ' + messageTrail).push(responseTime);
    if (check) continue;
    printError('t-OPRF test ' + messageTrail + ` #${i} failed`);
    printError('Result:\n' + result.toString());
    printError('Response:\n' + resp.toString());
    return false;
  }
  print('t-OPRF tests ' + messageTrail + ' successful.');
  if (!resultMap)
    return times;
  for (const [key, value] of times) {
    resultMap.set(key, value);
  }
  return resultMap;
}

/**
 * Tests OPRF. Randomly generates the key.
 * Chooses a random key uniform in group exponents and
 * completes an OPRF within itself. How oblivious...
 * @param {string} secret Client input
 * @return {Promise<boolean>} Whether the tests are successful
 */
async function testOPRF(it=5, resultMap) {
  const times = new Map([
    ['OPRF Mask', []],
    ['OPRF Challenge', []],
    ['OPRF Response', []]
  ]);
  const G = new PrimeGroup();
  const secret = 'This is some very secret message '+
      'to send over a secure channel.';
  let Hp_x = await groupHash(secret, G);
  Hp_x = new BigIntegerAdapter(Hp_x, 16);
  for (let i = 1; i <= it; i++) {
    const key = G.randomExponent();
    const result = Hp_x.powMod(key, G.modulus);
    var t0 = performance.now();
    const [rho, alpha] = await oprfMask(secret, G);
    var t1 = performance.now();
    const maskTime = (t1 - t0);
    t0 = performance.now();
    const beta = await oprfChallenge(alpha, key, G);
    t1 = performance.now();
    const challengeTime = (t1 - t0);
    t0 = performance.now();
    const resp = await oprfResponse(beta, rho, G);
    t1 = performance.now();
    const responseTime = (t1 - t0);
    const check = result.eqMod(resp, G.modulus);
    times.get('OPRF Mask').push(maskTime);
    times.get('OPRF Challenge').push(challengeTime);
    times.get('OPRF Response').push(responseTime);
    if (check) continue
    printError('OPRF test #' + i + ' failed.')
    printVerbose(`key: ${key.toString(16)} \n`);
    printVerbose(`result: ${result.toString(16)} \n`);
    printVerbose(`rho: ${rho.toString(16)} \n`);
    printVerbose(`alpha: ${alpha.toString(16)} \n`);
    printVerbose(`beta: ${beta.toString(16)} \n`);
    printVerbose(`resp: ${resp.toString(16)} \n`);
    return false;
  }
  print('OPRF tests successful.');
  if (!resultMap)
    return times;
  for (const [key, value] of times) {
    resultMap.set(key, value);
  }
  return resultMap;
}

/**
 * Tests Compartmented Secret Sharing
 * @param {[int]} bucketSizes Compartment sizes
 * @param {[int]} bucketThresholds Compartment thresholds
 * @param {int} it Iteration count 
 */
function testCompartmented(bucketSizes, bucketThresholds, it, resultMap) {
  const messageTrail = `([${bucketSizes}], [${bucketThresholds}])`;
  const times = new Map([
    ['Compartmented SS Generate ' + messageTrail, []],
    ['Compartmented SS Combine ' + messageTrail, []],
  ]);
  const G = new PrimeGroup();
  for (let i = 1; i <= it; i++) {
    const secret = G.randomExponent();
    var t0 = performance.now();
    const compShares = compartmentedGenShares(secret, bucketSizes,
      bucketThresholds, G);
    var t1 = performance.now();
    const genTime = (t1 - t0);
    if (VERBOSE) { // This redundant check may reduce unnecessary loops
      printVerbose('Generated shares:');
      compShares.forEach(function(shares, compartment) {
        printVerbose('\tShares of compartment #' + compartment);
        shares.forEach(function(share, index) {
          printVerbose('\t\tShare #' + index + ': ' + share[1].toString(16));
        });
      });
    }
    var t0 = performance.now();
    const recons = compartmentedCombineShares(compShares, G);
    var t1 = performance.now();
    const combineTime = (t1 - t0);
    printVerbose('Secret reconstructed:');
    printVerbose('\tOriginal secret: ' + secret.toString(16));
    printVerbose('\tReconstructed secret: ' + recons.toString(16));
    const check = secret.eqMod(recons, G.order);
    times.get('Compartmented SS Generate ' + messageTrail).push(genTime);
    times.get('Compartmented SS Combine ' + messageTrail).push(combineTime);
    if (check) continue;
    printError('Compartmented SS test ' + messageTrail + ` #${i} failed`);
    printError('Secret:\n' + secret.toString(16));
    printError('Recons:\n' + recons.toString(16));
    return false;
  }
  print('Compartmented SS tests ' + messageTrail + ' successful.');
  if (!resultMap)
    return times;
  for (const [key, value] of times) {
    resultMap.set(key, value);
  }
  return resultMap;
}

/**
 * Tests Shamir's Secret Sharing on base or exponenets.
 * @param {int} n Share count
 * @param {int} t Threhsold
 * @param {int} it Iteration count
 * @param {boolean?} exponent Whether the work is done on exponents
 * @param {Map} resultMap Map object holding previous tests results
 * @return {boolean} Whether the tests are successful
 */
function testShamir(n, t, it, exponent=false, lambdas=false, resultMap) {
  const messageTrail = `(${n}, ${t}) on ` + (exponent ? 'exponent':'base')+
  (lambdas ? ' (lambdas pre-calculated)' : '');
  const times = new Map([
    ['Shamir SS Generate ' + messageTrail, []],
    ['Shamir SS Combine ' + messageTrail, []],
  ]);
  const G = new PrimeGroup();
  const modulus = G.modulus;
  const order = G.order;
  for (let i = 1; i <= it; i++) {
    const secret = G.randomExponent();
    var t0 = performance.now();
    const shares = shamirGenShares(secret, n, t, G);
    var t1 = performance.now();
    const genTime = (t1 - t0);
    if (VERBOSE) { // This redundant check may reduce unnecessary loops
      printVerbose('Generated shares:');
      for (const share of shares) {
        printVerbose('\tShare #' + share[0] + ': ' + share[1].toString(16));
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
    if (lambdas) {
      for (const point of shares) {
        point.push(calculateLambda(point[0], t, G.order));
      }
    }
    t0 = performance.now();
    const recons = shamirCombineShares(shares.slice(0, t), G, exponent);
    t1 = performance.now();
    const combineTime = (t1 - t0); 
    printVerbose('Secret reconstructed:');
    printVerbose('\tOriginal secret: ' + secret.toString(16));
    printVerbose('\tReconstructed secret: ' + recons.toString(16));
    const check = exponent ?
      secret_elm.eqMod(recons, modulus) : secret.eqMod(recons, order);
    times.get('Shamir SS Generate ' + messageTrail).push(genTime);
    times.get('Shamir SS Combine ' + messageTrail).push(combineTime);
    if (check) continue;
    printError('Shamir SS ' + messageTrail + ' test #' + i + ' failed.');
    printError('Secret:\n' + secret.toString(16));
    printError('Recons:\n' + recons.toString(16));
    return false;
  }
  print('Shamir SS ' + messageTrail + ' tests successful.');
  if (!resultMap)
    return times;
  for (const [key, value] of times) {
    resultMap.set(key, value);
  }
  return resultMap;
}

/**
 * Tests the BigInteger library performance.
 * Only necessary for debug purposes and only prints values.
 */
function testBigInt(it=500) {
  // Divide functions into different arrays depending on parameters 
  const simpleFunctions = ['bitLen', 'probPrime', 'toString']; // no input functions
  const numFunctions = ['add', 'subtract', 'mul', 'divide','eq', 'leq', 'geq', 'lesser', 'greater']; // Not pow, it goes out of range with random numbers
  const modFunctions = ['mod', 'randomMod'] // Not invMod, coprime numbers needed
  const nmFunctions = ['addMod', 'subtractMod', 'mulMod', 'powMod', 'eqMod']; // num and mod input functions
  const lenFunctions =['randomLen', 'randomPrime'];

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
 * TODO: This isn't useful in its current state. Time each function individually.
 * Tests polynomial operations. Only useful for debugging purposes.
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
 * TODO: Time each group function individually.
 * Tests group generation.
 */
function testGroup() {
  console.time('Random PrimeGroup Generation');
  const G = new PrimeGroup();
  console.timeEnd('Random PrimeGroup Generation');
  print('New PrimeGroup generated.');
  print('Modulus: ' + G.modulus.toString(16));
  print('Order: ' + G.order.toString(16));
  print('Generator: ' + G.generator.toString(16));
}

// --- Tests end ---
// --- Cryptographic Signature Functions ---
/**
 * Wrapper for the sign function of Subtle interface of WebCrypto API;
 * returns a promise resolving to a RSASSA-PKCS1 v1.5 signature on the given message.
 * @param {string} message User input, to be signed
 * @param {CryptoKey} privateKey Previously generated CryptoKey
 * @return {Promise<ArrayBuffer>} Signature
 */
async function sign(message, privateKey) {
  const Crypto = importCrypto();
  const encoded = new TextEncoder().encode(message);
  return await Crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    encoded
  );
}

/**
 * Wrapper for the verify function of Subtle interface of WebCrypto API;
 * verifies an RSASSA-PKCS1 v1.5 signature on the given message.
 * @param {string} message User input, to be signed
 * @param {ArrayBuffer} signature Signature generated with 'sign()'
 * @param {CryptoKey} publicKey Previously generated CryptoKey 
 * @return {Promise<bool>} True if the signature is valid
 */
async function verify(message, signature, publicKey) {
  const Crypto = importCrypto();
  const encoded = new TextEncoder().encode(message);
  return await Crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    publicKey,
    signature,
    encoded
  );
}

/**
 * Wrapper for the generateKey function of Subtle interface of WebCrypto API;
 * Generates an RSAASSA-PKCS1 v1.5 key pair of specified bit length.
 * After the returned promise is resolved, the resolving object has the fields
 * pair.privateKey and pair.publicKey.
 * @param {int} bitLen Length of the generated keys. Defaults to 2048.
 * @return {Promise<CryptoKeyPair>} (privKey, pubKey)
 */
async function generateSignatureKeys(bitLen=2048) {
  const Crypto = importCrypto();
  const keyPair = await Crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5', // Can also use RSA-PSS which uses a random salt
      modulusLength: bitLen,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  );
  return keyPair;
}
// --- Signature end ---
// --- Symmetric Encryption Functions ---
//TODO: Support for enc/dec with key instead of password.
/**
 * Wrapper for the decrypt function of the Subtle interface of WebCrypto API.
 * Encrypts a plaintext using AES-CTR with 64-bit blocks.
 * Note that this is not an authenticated encryption scheme.
 * TODO: Let caller choose encryption and hash functions.
 * @param {BigIntegerAdapter | string} message  Original plaintext
 * @param {string} password User input to derive the encryption key
 * @param {string} hashFunction Used for key derivation (PBKDF2), i.e., "SHA-256"
 * @param {int} iterations Used for key derivation (PBKDF2)
 * @param {int} saltLen Used for key derivation (PBKDF2)
 * @return {Promise<[ArrayBuffer, Uint8Array, Uint8Array]>} [ciphertext, counter, salt]
*/
async function encrypt(message, password, hashFunction, iterations, saltLen) {
  if (message instanceof BigIntegerAdapter)
  message = message.toString(16);
const enc = new TextEncoder();
const Crypto = importCrypto();
const plaintext = enc.encode(message);
const salt = Crypto.getRandomValues(new Uint8Array(saltLen));
const key  = await deriveEncryptionKey(enc.encode(password), hashFunction, iterations, salt);
let counter = Crypto.getRandomValues(new Uint8Array(16));
let ciphertext = await Crypto.subtle.encrypt(
  {
    name: 'AES-CTR',
    counter,
    length: 64
  },
  key,
  plaintext);
  return [ciphertext, counter, salt];
}

/**
 * Wrapper for the decrypt function of the Subtle interface of WebCrypto API.
 * Decrypts a ciphertext encrypted using AES-CTR with 64-bit blocks.
 * Note that this is not an authenticated encryption scheme.
 * @param {ArrayBuffer} ciphertext generated by 'encrypt()'
 * @param {string} password User input to derive the decryption key
 * @param {string} hashFunction Used for key derivation (PBKDF2), i.e., "SHA-256"
 * @param {int} iterations Used for key derivation (PBKDF2)
 * @param {Uint8Array} salt Used for key derivation (PBKDF2)
 * @param {Uint8Array} counter generated by 'encrypt()'
 * @return {Promise<string>} Decrypted plaintext
 */
async function decrypt(ciphertext, password, hashFunction, iterations, salt, counter) {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const Crypto = importCrypto();
  const key = await deriveEncryptionKey(enc.encode(password), hashFunction, iterations, salt);
  const decrypted = await Crypto.subtle.decrypt(
    {
      name: 'AES-CTR',
      counter,
      length:64
    },
    key,
    ciphertext);
  return dec.decode(decrypted);
}

/**
 * Wrapper for the deriveKey function of the Subtle interface of WebCrypto API.
 * Derives a 256-bit encryption key to be used for AES-CTR with 64-bit blocks from
 * the given password. Uses PBKDF2.
 * @param {ArrayBuffer} encodedPw Password encoded with TextEncoder
 * @param {string} hashFunction A Cryptographic hash function, i.e., SHA-256
 * @param {int} iterations Iterations of PBKDF2
 * @param {Uint8Array} salt Random salt for PBKDF2
 * @returns {Promise<CryptoKey>} Symmetric encryption key
 */
async function deriveEncryptionKey(encodedPw, hashFunction, iterations, salt) {
  const Crypto = importCrypto();
  const keyMaterial = await Crypto.subtle.importKey(
    'raw',
    encodedPw,
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']);
  const key = await Crypto.subtle.deriveKey(
    {
      'name': 'PBKDF2',
      salt: salt,
      'iterations': iterations,
      'hash': hashFunction
    },
    keyMaterial,
    {'name': 'AES-CTR', 'length': 256},
    true,
    ['encrypt', 'decrypt']);
  return key;
}

/**
 * Wrapper for the exportKey function of the Subtle interface of WebCrypto API.
 * Exports a key from a CryptoKey object into portable format.
 * @param {CryptoKey} key to be exported
 * @returns {Promise<ArrayBuffer>} Raw data of the key
 */
async function exportKey(key) {
  //TODO: Add other formats here too.
  const Crypto = importCrypto();
  return await Crypto.subtle.exportKey('raw', key);
}

/**
 * Wrapper for the importKey function of the Subtle interface of WebCrypto APIç
 * Imoprts a key from portable format into a CryptoKey object.
 * @param {ArrayBuffer} keyData Raw data of the key
 * @returns {Promise<CryptoKey>} CryptoKey object constructed from the data
 */
async function importKey(keyData) {
  const Crypto = importCrypto();
  return await Crypto.subtle.importKey(
   'raw',
    keyData,
    'AES-CTR',
    true,
    ['encrypt', 'decrypt']);
}
/// --- Symmetric Encryption end ---
// --- Identification Scheme Functions ---
// Schnorr scheme according to: https://asecuritysite.com/encryption/schnorr
// I used the same notation for the variables for clarity.

/**
 * Generates a random exponent from the common PrimeGroup to be used as challenge.
 * @param {PrimeGroup} group The group in which the operations are done 
 * @return {BigIntegerAdapter} 'c': Random challenge
 */
function schnorrChallenge(group) {
  return group.randomExponent();
}

/**
 * * Note: public key is calculated here.
 * Generates a responds to the challenge, proving knowledge of x.
 * Note that X = g^x is normally assumed to be known, because the
 * public key is (g^x, group). For the sake of simplicity, it is
 * returned here; as this has little effect on performance numbers.
 * @param {BigIntegerAdapter} x The secret value to be proven, an
 *  exponent in the group
 * @param {BigIntegerAdapter} c The challenge sent by the challenger
 * @param {PrimeGroup} group The group in which the operations are done 
 * @return {[BigIntegerAdapter, BigIntegerAdapter, BigIntegerAdapter]} [X, Y, z]
 *  X = g^x the public key, Y = g^random and z = y*x^c the response.
 */
function schnorrResponse(x, c, group) {
  const mod = group.modulus;
  const ord = group.order;
  const g = group.generator;
  const X = g.powMod(x, mod);
  const y = group.randomExponent();
  const Y = g.powMod(y, mod);
  const z = y.addMod(x.mulMod(c, ord), ord);
  return [X, Y, z];
}

/**
 * Verifies that the prover has the private key corresponding to the public key X.
 * @param {BigIntegerAdapter} X The public key
 * @param {BigIntegerAdapter} Y First part of the response
 * @param {BigIntegerAdapter} z Second part of the response
 * @param {BigIntegerAdapter} c The challenge
 * @param {PrimeGroup} group The group in which the operations are done 
 * @return {bool} g^z == Y*X^c (in group)
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
/**
 * Generates shares from a secret according to Compartmented
 * Secret Sharing as presented in https://eprint.iacr.org/2005/408.pdf
 * Each compartment (bucket) has a threshold of its own,
 * allowing for an access control mechanism.
 * @param {string | BigIntegerAdapter} secret Secret to divide into shares,
 * a number or a string representing a number
 * @param {[int]} bucketSizes Sizes of compartments
 * @param {[int]} bucketThresholds Thresholds of compartments
 * @param {PrimeGroup} group The group in which the operations are done
 * @return {[[[int, BigIntegerAdapter]]]} Shares of compartments. Share
 * j of compartment i corresponds to shares[i][j].
 */
function compartmentedGenShares(secret, bucketSizes, bucketThresholds, group) {
  if (bucketSizes.length != bucketThresholds.length) {
    printError('bucketSizes and bucketThresholds sizes do not match.');
    return [];
  }
  if (typeof secret == 'string')
    secret = new BigIntegerAdapter(secret);
  const bucketCount = bucketSizes.length;
  const bucketSecrets = [];
  var total = new BigIntegerAdapter(0);
  for (let i = 1; i < bucketCount; i++) {
    const randomExponent = group.randomExponent();
    total = total.addMod(randomExponent, group.order);
    bucketSecrets.push(randomExponent);
  }
  bucketSecrets.push(secret.subtractMod(total, group.order)); // Sum of bucketSecrets = secret
  const shares = [];
  for (let i = 0; i < bucketCount; i++) {
    shares.push(shamirGenShares(bucketSecrets[i], bucketSizes[i], bucketThresholds[i], group));
  }
  return shares;
}

/**
 * Combines shares to reveal a secret according to Compartmented
 * Secret Sharing as presented in https://eprint.iacr.org/2005/408.pdf
 * Does not check for the correctness of shares. If the shares
 * are input incorrectly, generates a wrong output.
 * @param {[[[int, BigIntegerAdapter]]]} shares Shares of compartments
 * @param {PrimeGroup} group The group in which the operations are done 
 * @returns {BigIntegerAdapter} The reconstructed secret
 */
function compartmentedCombineShares(shares, group) {
  const bucketCount = shares.length;
  var secret = new BigIntegerAdapter(0);
  for (let i = 0; i < bucketCount; i++) {
    const bucketSecret = shamirCombineShares(shares[i], group);
    secret = secret.addMod(bucketSecret, group.order);
  }
  return secret;
}

/**
 * Generate shares from a secret according to Shamir's Secret Sharing
 * @param {string | BigIntegerAdapter} secret Secret to divide into shares,
 * a number or a string representing a number
 * @param {int} n Share count
 * @param {int} t Threhsold
 * @param {PrimeGroup} group The group in which the operations are done 
 * @return {[[int, BigIntegerAdapter]]} The shares that uniquely determine the
 * secret. Each share is an array of size two of the form [int, BigIntegerAdapter]
*/
function shamirGenShares(secret, n, t, group) {
  if (typeof secret == 'string')
    secret = new BigIntegerAdapter(secret);
  const pnomial = genPol(secret, t, group);
  const shares = [];
  for (let i = 1; i <= n; i++) {
    shares.push([i, evalPol(pnomial, i, group)]);
  }
  return shares;
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
 * IMPORTANT: During the pre-calculation of lambdas make sure
 * to use available share count for interpolation, not total
 * share count.
 *
 * @param {[[int, BigIntegerAdapter, BigIntegerAdapter?]]} shares A vector of shares 
 * corresponding to [shareIndex, shareValue, shareLambda]. shareLambda
 * is only input when lambdas are pre-calculated.
 * @param {PrimeGroup} group The group in which the operations are done 
 * @param {boolean} exponent Determines whether the interpolation will
 * be done on the exponents. Internal t-OPRF specific use case.
 * @return {BigIntegerAdapter} The reconstructed secret
 */
function shamirCombineShares(shares, group, exponent=false) {
  const shareCount = shares.length;
  const mod = group.modulus;
  const ord = group.order;
  var at_0 = exponent ? new BigIntegerAdapter(1) : new BigIntegerAdapter(0);
  const lambdas = shares[0].length == 3;
  for (const point of shares) {
    const i = point[0]; // int, not bigInt
    const at_i = point[1];
    const lambda_i = lambdas ? point[2] : calculateLambda(i, shareCount, ord);
    if (exponent) at_0 = at_0.mulMod(at_i.powMod(lambda_i, mod), mod);
    else at_0 = at_0.addMod(at_i.mulMod(lambda_i, ord), ord);
  }
  return at_0;
}

/**
 * Calculates the Lagrange interpolation coefficient for x = i and x_0 = 0.
 * @param {int} i Point x
 * @param {int} shareCount Number of available shares
 * @param {BigIntegerAdapter} order Modulus of operations (group.order)
 * @return {int} Lambda_i: The Lagrange interpolation coefficient
 */
function calculateLambda(i, shareCount, order) {
  lambda_i = new BigIntegerAdapter(1);
  for (let j = 1; j <= shareCount; j++) {
    if (i == j) continue;
    const inv = (new BigIntegerAdapter(j-i)).invMod(order); // 1/j-i
    const temp = inv.mulMod(j, order); // j/j-i
    lambda_i = lambda_i.mulMod(temp, order);
  }
  return lambda_i;
}

/**
 * Constructs a degree t-1 semi-random polynomial.
 * All coefficients are exponents in the given group.
 * @param {BigIntegerAdapter} constant Constant term
 * @param {int} t Length of polynomial
 * @param {PrimeGroup} group The group in which the operations are done 
 * @return {[BigIntegerAdapter]} An array of polynomial coefficients,
 * representing a polynomial of degree t-1 with a_0 = contant,
 * a_i = random for all 0<i<t.
 */
function genPol(constant, t, group) {
  const pnomial = [constant];
  for (let i = 1; i < t; i++) {
    const rand = group.randomExponent();
    pnomial.push(rand);
  }
  return pnomial;
}

/**
 * Evaluates a polynomial at a point in a group.
 * @param {[BigIntegerAdapter]} pol An array representing a polynomial
 * @param {int} x The point on which to evaluate the polynomial
 * @param {PrimeGroup} group The group in which the operations are done 
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
 * Creates the masked text to be sent to each SP.
 * Call this function once, and send alpha to each SP.
 * This returns a promise resolving to [rho, alpha], the SPs will
 * respond with beta_i = alpha^k_i and c_i.
 * This function also returns rho, which should be kept secret and only
 * be used as an input to the reconstructPassword function.
 * @param {string} secret Client input to OPRF
 * @param {PrimeGroup} group The group in which the operations are done 
 * @return {Promise<[BigIntegerAdapter, BigIntegerAdapter]>} [rho, alpha]:
 * A pair holding the random number rho and alpha= Hp_x^rho
*/
async function oprfMask(secret, group) {
  const rho = group.randomElement();
  const Hp_x = await groupHash(secret, group);
  printVerbose('Hp_x: ' + Hp_x);
  let Hp_xToRho = new BigIntegerAdapter(Hp_x, 16);
  Hp_xToRho = Hp_xToRho.powMod(rho, group.modulus);
  return [rho, Hp_xToRho];
}

/**
 * Generates the challenge alpha^k.
 * @param {BigIntegerAdapter} alpha Hp_x^rho received from client
 * @param {BigIntegerAdapter} k The OPRF key, secret value
 * @param {PrimeGroup} group The group in which the operations are done 
 * @return {Promise<BigIntegerAdapter>} beta = alpha^k
*/
async function oprfChallenge(alpha, k, group) {
  return alpha.powMod(k, group.modulus);
}

/**
 * Calculates beta^(rho^-1) = alpha^(k*(rho^-1)) = Hp_x^(rho*k*(rho^-1)) = Hp_x^k.
 * If using t-OPRF, pass betas as an array. Otherwise pass a BigIntegerAdapter.
 * @param {[BigIntegerAdapter] | BigIntegerAdapter} betas Either beta (on OPRF)
 * or an array of betas (on t-OPRF).
 * @param {BigIntegerAdapter} rho The random number previously calculated
 * using oprfMask()
 * @param {PrimeGroup} group The group in which the operations are done 
 * @return {Promise<BigIntegerAdapter>} The output of OPRF: Hp_x^k
 */
async function oprfResponse(betas, rho, group) {
  const threshold = !(betas instanceof BigIntegerAdapter);
  // betas is actually a single beta in the below case
  if (!threshold) return betas.powMod(rho.invMod(group.order), group.modulus);
  const lambdas = betas[0].length == 3;
  const shares = [];
  for (const beta of betas) {
    const index = beta[0];
    const toRoInv = await oprfResponse(beta[1], rho, group);
    const share = [index, toRoInv];
    if (lambdas) share.push(beta[2]);
    shares.push(share);
  }
  return shamirCombineShares(shares, group, true);
}

// --- OPRF end ---
// --- Hash functions ---
/**
 * Hashes a string to an element in the given group.
 * Returns a promise resolving to the hash as a hex string.
 * This is not fixed sized output, though.
 * @param {string} str To digest into hash
 * @param {PrimeGroup} group The group in which the operations are done 
 * @return {Promise<string>} Hp(str) in hexadecimal string form
 */
async function groupHash(str, group) {
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
 * @param {string} str To digest into hash
 * @return {Promise<string>} SHA-256(str) in hexadecimal string form
 */
async function hash(str) {
  const enc = new TextEncoder();
  const data = enc.encode(str);
  const Crypto = importCrypto();
  let hash = await Crypto.subtle.digest('SHA-256', data);
  hash = Buffer.from(hash).toString('hex');
  // Converstion to string may reduce size only when there
  //  are 0s on the left side
  while (hash.length < 32) hash = '0' + hash;
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
   * @param {BigIntegerAdapter} oLen
   * @param {BigIntegerAdapter} stat
   * @throws {RangeError} If the generated primes do not satisfy
   * given bit length conditions. If this is thrown, there is
   * a bug with prime generation, so this should never happen
   * under normal circumstances.
   */
  constructor(modLen, oLen, stat) {
    // Check preconditions
    if(!modLen) {
      // Precalculated PrimeGroup
      printDebug('Generating PrimeGroup with default values because no'+
      ' parameters were passed while calling the constructor.');
      this.modulus = new BigIntegerAdapter('b711fc4246f321077b5bc68005c4'+
      'a3d0f4c4c9451c2399b09966dda4321f8126bda76eb228862ac1e2a97abf66e17'+
      'b807cef65eaa32ecb0cacb3e735d9eb3f34cc789a2816c05e3c5a05ff7dd7209b'+
      '7f3790f9af5e2888c7efb22d83ebb9d384496f469973f9dd4b666aabecfec5ba4'+
      'c94d6942fff51e243d833e58146042f9aae4ea44d7df227133d25e2a995d4816f'+
      '8488d3b5855698f9b457900b7b96295c5b5a358192d0aa29b90c05f2658e343e3'+
      'c41bbdf879fa6bf310a48084295c0d2af5bc1f722546f6631c18ba656a11a4187'+
      'eeaeb32b6a4ba6569c039853635f1e854507c99153caa16394b5a477c1ff40817'+
      '81ab7522030ce900974543a621f9f', 16);
      this.order = new BigIntegerAdapter('bfaa6a98c30984b4817b9d56ade59a'+
      '645de2598fd8b566f9de083eb014964b27', 16);
      this.generator = new BigIntegerAdapter('2b0dfcdd512e038eb3b92c1fcb'+
      'e099a2bbd9ef2777756c4e90c4667d6f688c9284c898d0850b5c061659529d790'+
      '2aeeadc3922e59beba98642fde4105eb6f2642dde8a3a2d0bdaf139b57c22f52f'+
      '717f3c4667152f9ed1c29bff5baca42d247af3d27f0a7bb8a852c92278d738e9f'+
      '65d13213448d02d073ba0aa7c228c1aadd843f00e30e8bb511a9fde82ca599629'+
      'fafeaeca2577909816f7a3a7a2e5455f449ad0a47165ae0e8ae2deddb9f1c6288'+
      '15d66f25d0b9c1ae1a202557d83488b6a118f38c3121374d2d6664976b591b69e'+
      'c19103b8106082c75d4e3bf7975fa5810c47d0bdbd0510adc8084da400e7746b6'+
      '832f2bf054d17b4858bd3839a644594', 16);
      return;
    }

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
      printDebug('Generated potential modulus: ' + t1-t0 + ' ms');
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

  /**
   * Returns a random BigInteger exponent.
   */
  randomExponent() {
    return BigIntegerAdapter.randomMod(this.order);
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
    const Crypto = importCrypto();
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
    // TODO: Handle biasing
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
/**
 * Writes a Map object into a CSV file.
 * @param {Map} map 
 * @param {string} filename
 * @param {boolean} append
 */
function exportToCSV(map, filename, append=false) {
  const fs = require('fs');
  const keys = Array.from(map.keys());
  const vals = Array.from(map.values());
  var fd;
  const sep = ';';
  var success = true;
  try {
    fd = append ? fs.openSync(filename, 'a') : fs.openSync(filename, 'w');
    var row = '';
    if (!append) {
      for (const key of keys) {
        row += key + sep;
      }
      row = row.slice(0, row.length-1) + '\n';
      fs.appendFileSync(fd, row, 'utf8');
    }
    for (let i = 0; i < vals[0].length; i++) {
      row = '';
      for (const val of vals) {
        row += val[i] + sep;
      }
      row = row.slice(0, row.length-1) + '\n';
      fs.appendFileSync(fd, row, 'utf8');
    }
  } catch (err) {
    printError('Writing to CSV unsuccessful.')
    printError(err);
    success = false;
  } finally {
    if (fd !== undefined)
      fs.closeSync(fd);
    return success;
  }
}

function importCrypto() {
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
  // ! Printing with color does not work
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

// --- Exports ---

module.exports = {
  sign, verify, generateSignatureKeys, decrypt, encrypt,
  deriveEncryptionKey, exportKey, importKey, schnorrChallenge, schnorrResponse,
  schnorrVerify, compartmentedGenShares, compartmentedCombineShares, shamirGenShares, shamirCombineShares,
  calculateLambda, genPol, evalPol, oprfResponse, oprfChallenge,
  oprfMask, groupHash, hash, PrimeGroup, BigIntegerAdapter,
  importCrypto, toArrayBuffer, print, printDebug, printVerbose,
  printError
}

// --- Exports end ---

// This check protects importing scripts from running main().
if (typeof require != 'undefined' && require.main == module) {
  main();
}
