# browser-crypto-lib by Crypto-KU

[![NPM version](https://img.shields.io/npm/v/browser-crypto-lib.svg)](https://www.npmjs.com/package/browser-crypto-lib)
[![Build Status](https://img.shields.io/travis/CRYPTO-KU/browser-crypto-lib.svg)](https://travis-ci.org/CRYPTO-KU/browser-crypto-lib)

- Note: The above links are not yet initialized.

browser-crypto-lib is a portable and modular JavaScript library providing cryptographic utilities in the browser and Node.js environments. It focuses on ease of use and performance testing. It serves as a wrapper for other libraries when applicable, and implements some other functionality.

browser-crypto-lib should only be used for proof of concept and research applications. The code must be reviewed by security experts for security reliant applications.

browser-crypto-lib makes use of third party node.js modules; so, a tool such as [Browserify](https://browserify.org) should be used for browser compatibility. This is a straightforward extra step that makes the process of coding for browsers easier.

The library is not yet complete as some functionalities are still being implemented and the code is being refactored.

## Features
- Easy to use cryptographic functions
- Cryptographic Hashing
- Digital Signatures
- Symmetric and Asymmetric Encryption
- Shamir's Secret Sharing
- Compartmented Secret Sharing
- OPRF (Oblivious Pseudorandom Function)
- t-OPRF (Threshold OPRF)
- Schnorr Identification Scheme
- Big Integers
  - An adapter class BigIntegerAdapter is exported. To use another big integer library, add wrappers for the calls inside this class.
- Randomly Generated Prime Groups
  - Note: The performance is quite poor with the generation of Prime groups
- Includes the functionality for performance tests for each function.
  - Running the library runs the tests by default, but importing does not.

# Usage
## Initializing

### Using Node.js
```javascript
const cryptolib = require('browser-crypto-lib');
```

### Setting up for browser usage using [Browserify](https://browserify.org)

After importing browser-crypto-lib and optionally other Node.js modules in the source file, for example *main.js*, simply call:
```console
~$ browserify main.js -o bundle.js
```
This bundles up the node modules into a browser compatible source file *bundle.js*. Later, *bundle.js* can be included into a HTML document.
```html
<script src="bundle.js"></script>
```

Note that after making any changes to *main.js*, browserify should be called again to re-bundle the code.

## API Reference

### <a name="sign"></a>`async sign(message, privateKey)`

**Description:**

Wrapper for the sign function of Subtle interface of WebCrypto API;
returns a promise resolving to a RSASSA-PKCS1 v1.5 signature on the given message.

**Parameters:**

- `message` (`string`): User input, to be signed
- `privateKey` (`CryptoKey`): Previously generated CryptoKey

**Returns:**

- `Promise<ArrayBuffer>`: Signature

**Example:**

```javascript
const signature = await sign('Some message to be signed', privateKey);
```

### <a name="verify"></a>`async verify(message, signature, publicKey)`

**Description:**

Wrapper for the verify function of Subtle interface of WebCrypto API;
verifies an RSASSA-PKCS1 v1.5 signature on the given message.

**Parameters:**

- `message` (`string`): User input, to be signed
- `signature` (`ArrayBuffer`) Signature generated with [`sign()`](#sign)
- `public` (`CryptoKey`): Previously generated CryptoKey

**Returns:**

- `Promise<bool>`: True if the signature is valid

**Example:**

```javascript
const check = await verify('Some message to be signed', signature, publicKey);
```

### <a name="gen-sig-keys"></a>`async generateSignatureKeys(bitLen?)`

**Description:**

Wrapper for the generateKey function of Subtle interface of WebCrypto API;
Generates an RSAASSA-PKCS1 v1.5 key pair of specified bit length.
After the returned promise is resolved, the resolving object has the fields
pair.privateKey and pair.publicKey.

**Parameters:**

- `bitLen?` (`int`): Length of the generated keys. Defaults to 2048.

**Returns:**

- `Promise<CryptoKeyPair>`: (*privKey, pubKey*)

**Example:**

```javascript
const keyPair = await generateSignatureKeys(); // Generates an 2048-bit-long key pair.
const pubKey = keyPair.publicKey;
const privKey = keyPair.privateKey;
```

### <a name="encrypt"></a>`async encrypt(message, password, hashFunction, iterations, saltLen)`

**Description:**

Wrapper for the decrypt function of the Subtle interface of WebCrypto API.
Encrypts a plaintext using AES-CTR with 64-bit blocks.
Note that this is not an authenticated encryption scheme.

**Parameters:**

- `message` (`BigIntegerAdapter | string`): Original plaintext
- `password` (`string`): User input to derive the encryption key
- `hashFunction` (`string`): Used for key derivation (PBKDF2), i.e., "SHA-256"
- `iterations` (`int`): Used for key derivation (PBKDF2)
- `saltLen` (`int`): Used for key derivation (PBKDF2)

**Returns:**

- `Promise<[ArrayBuffer, Uint8Array, Uint8Array]>`: `[ciphertext, counter, salt]`

**Example:**

```javascript
const plaintext = "Some very important message that we shall encrypt.";
const password = "A secure password";
const hashFunction = "SHA-256";
const pbkdfIterations = 100000;
const saltLen = 5;
const [ciphertext, counter, salt] = await encrypt(plaintext, password, hashFunction, pkdfIterations, saltLen);
```

### <a name="decrypt"></a>`async decrypt(ciphertext, password, hashFunction, iterations, salt, counter)`

**Description:**

Wrapper for the decrypt function of the Subtle interface of WebCrypto API.
Decrypts a ciphertext encrypted using AES-CTR with 64-bit blocks.
Note that this is not an authenticated encryption scheme.

**Parameters:**

- `ciphertext` (`ArrayBuffer`): Ciphertext generated by [`encrypt()`](#encrypt)
- `password` (`string`): User input to derive the encryption key
- `hashFunction` (`string`): Used for key derivation (PBKDF2), i.e., "SHA-256"
- `iterations` (`int`): Used for key derivation (PBKDF2)
- `salt` (`Uint8Array`): Used for key derivation (PBKDF2)
- `counter` (`Uint8Array`): Counter generated by [`encrypt()`](#encrypt)

**Returns:**

- `Promise<string>`: Decrypted plaintext

**Example:**

```javascript
const decrypted = await decrypt(ciphertext, password, hashFunction, iterations, salt, counter);
console.log(decrypted)
```
```plaintext
Output: Some very important message that we shall encrypt.
```

### <a name="deriveEncKey"></a>`async deriveEncryptionKey(encodedPw, hashFunction, iterations, salt)`

**Description:**

Wrapper for the deriveKey function of the Subtle interface of WebCrypto API.
Derives a 256-bit encryption key to be used for AES-CTR with 64-bit blocks from
the given password. Uses PBKDF2.
This function is embedded into the encrypt/decrypt functions.

**Parameters:**
- `encodedPw` (`ArrayBuffer`): Password encoded with TextEncoder
- `hashFunction` (`string`): A Cryptographic hash function, i.e., "SHA-256"
- `iterations` (`int`): Iterations of PBKDF2
- `salt` (`Uint8Array`): Random salt for PBKDF2

**Returns:**
- `Promise<CryptoKey>`: Symmetric encryption key

**Example:**

```javascript
const Crypto = importCrypto();
// Use importCrypto() to import the embedded crypto dependency when needed, ...
// ... otherwise browser compatibility is broken after Browserify.
const enc = new TextEncoder();
const password = "A secure password";
const hashFunction = "SHA-256";
const pbkdfIterations = 100000;
const salt = Crypto.getRandomValues(new Uint8Array(5)); // Array of 5 8-bit integers
const key  = await deriveEncryptionKey(enc.encode(password), hashFunction, iterations, salt);
```

### <a name="exportKey"></a>`async exportKey(key)`

**Description:**

Wrapper for the exportKey function of the Subtle interface of WebCrypto API.
Exports a key from a CryptoKey object into portable format.

**Parameters:**
- `key` (`CryptoKey`): Key to be exported

**Returns:**
- `Promise<ArrayBuffer>`: Raw data of the key

**Example:**

```javascript
const keyData = await exportKey(key);
```

### <a name="importKey"></a>`async importKey(keyData)`

**Description:**

Wrapper for the importKey function of the Subtle interface of WebCrypto API.
Imoprts a key from portable format into a CryptoKey object.

**Parameters:**
- `keyData` (`ArrayBuffer`): Raw data of the key

**Returns:**
- `Promise<CryptoKey>`: CryptoKey object constructed from the data

**Example:**

```javascript
const key = await importKey(keyData);
```

### <a name="schnorrChallenge"></a>`schnorrChallenge(group)`

**Description:**

Generates a random exponent from the common PrimeGroup to be used as challenge.

**Parameters:**
- `group` (`PrimeGroup`): The group in which the operations are done 

**Returns:**
- `BigIntegerAdapter`: Random challenge

**Example:**

```javascript
const group = new PrimeGroup();
const c = schnorrChallenge(group);
```

### <a name="schnorrResponse"></a>`schnorrResponse(x, c, group)`

**Description:**

Generates a responds to the challenge, proving knowledge of $x$.
Note that $X = g^x$ is normally assumed to be known, because the
public key is ($g^x$, group). For the sake of simplicity, it is
returned here; as this has little effect on performance numbers.

*Note: Public key is calculated here.*

**Parameters:**
- `x` (`BigIntegerAdapter`): The secret value to be proven, an exponent in the group
- `c` (`BigIntegerAdapter`): The challenge sent by the challenger
- `group` (`PrimeGroup`): The group in which the operations are done
  
**Returns:**
- `[BigIntegerAdapter, BigIntegerAdapter, BigIntegerAdapter]`: `[$X, Y, z$]`: $X = g^x$ the public key, $Y= g^\text{random}$, $z = y*x^c$ the response.

**Example:**

```javascript
const group = new PrimeGroup();
const secret = group.randomExponent();
const resp = schnorrResponse(secret, c, group);
```

### <a name="schnorrVerify"></a>`schnorrVerify(X, Y, z, c, group)`

**Description:**
Verifies that the prover has the private key corresponding to the public key $X$.

**Parameters:**
- `X` (`BigIntegerAdapter`): The public key
- `Y` (`BigIntegerAdapter`): First part of the response
- `z` (`BigIntegerAdapter`): First part of the response
- `c` (`BigIntegerAdapter`): The challenge
- `group` (`PrimeGroup`): The group in which the operations are done
**Returns:**
- `bool`: $g^z == Y*X^c$ (in group)

**Example:**

```javascript
const group = new PrimeGroup();
const secret = group.randomExponent();
const resp = schnorrResponse(secret, c, group);
```

### <a name="compartmentedGenShares"></a>`compartmentedGenShares(secret, bucketSizes, bucketThreshold, group)`

**Description:**

Generates shares from a secret according to Compartmented
Secret Sharing as presented in [Compartmented Secret Sharing Based on the Chinese Remainder Theorem, Sorin Iftene, 2005.](https://eprint.iacr.org/2005/408.pdf)
Each compartment (bucket) has a threshold of its own,
allowing for an access control mechanism.

**Parameters:**

- `secret` (`BigIntegerAdapter`): Secret to divide into shares
- `bucketSizes` (`[int]`): Sizes of compartment
- `bucketThresholds` (`[int]`): Thresholds of compartments
- `group` (`PrimeGroup`): The group in which the operations are done
  
**Returns:**

- `[[[int, BigIntegerAdapter]]]`: Shares of compartments. Share $j$ of compartment $i$ corresponds to `shares[i][j]`.

**Example:**

```javascript
const group = new PrimeGroup();
const secret = group.randomExponent();
const compShares = compartmentedGenShares(secret, [3, 3, 5, 2], [2, 2, 4, 1], group);
```

### <a name="compartmentedCombineShares"></a>`compartmentedCombineShares(shares, group)`

**Description:**

Combines shares to reveal a secret according to Compartmented
Secret Sharing as presented in [Compartmented Secret Sharing Based on the Chinese Remainder Theorem, Sorin Iftene, 2005.](https://eprint.iacr.org/2005/408.pdf)
Does not check for the correctness of shares. If the shares
are input incorrectly, generates a wrong output.

**Parameters:**

- `shares` (`[[[int, BigIntegerAdapter]]]`): Shares of compartments
- `group` (`PrimeGroup`): The group in which the operations are done
  
**Returns:**

- `BigIntegerAdapter`: The reconstructed secret

**Example:**

```javascript
const recons = compartmentedCombineShares(compShares, group);
```

### <a name="shamirGenShares"></a>`shamirGenShares(secret, n, t, group)`

**Description:**

Generate shares from a secret according to Shamir's Secret Sharing

**Parameters:**

- `secret` (`BigIntegerAdapter`): Secret to divide into shares
- `n` (`int`): Share count
- `t` (`int`): Threshold
- `group` (`PrimeGroup`): The group in which the operations are done
  
**Returns:**

- `[[int, BigIntegerAdapter]]`: The shares that uniquely determine the secret. Each share is an array of size two of the form `[int, BigIntegerAdapter]`.

**Example:**

```javascript
const group = new PrimeGroup();
const secret = group.randomExponent(); // Or something like "112345"
const shares = shamirGenShares(secret, 5, 3 group);
```

### <a name="shamirCombineShares"></a>`shamirCombineShares(shares, group, exponent?)`

**Description:**

Takes an array of indices and shares where the elements
are in the form [k, share #k]. Uses Lagrange interpolation
to combine the shares and returns the secret as a BigInteger.
Does not check for n, t values! If not enough shares are
given, simply returns a wrong value. Giving more than enough
shares does not change the output.
Pass lambdas as the third elements of shares if they are
precomputed, i.e., `shares[i] = [x_i, y_i, lambda_i]`. Otherwise
pass each share as tuples, i.e., `shares[i] = [x_i, y_i]`.

IMPORTANT: During the pre-calculation of lambdas make sure
to use available share count for interpolation, not total
share count.

**Parameters:**

- `shares` (`[[int, BigIntegerAdapter, BigIntegerAdapter?]]`): A vector of shares corresponding to `[shareIndex, shareValue, shareLambda]`. *shareLambda* should only be passed when lambdas are pre-calculated.
- `group` (`PrimeGroup`): The group in which the operations are done
- `exponent` (`bool`): Determines whether the interpolation will be done on the exponents. Internal t-OPRF specific use case. Defaults to false.
  
**Returns:**

- `BigIntegerAdapter`: The reconstructed secret

**Example:**

```javascript
const recons = shamirCombineShares(shares.slice(0, 3), group);
```

### <a name="calculateLambda"></a>`calculateLambda(i, shareCount, order)`

**Description:**

Calculates the Lagrange interpolation coefficient for $x=i$ and $x_0=0$.

**Parameters:**

- `i` (`int`): Point $x$
- `shareCount` (`int`): Number of available shares
- `order` (`BigIntegerAdapter`): Modulus of operations, `group.order`
  
**Returns:**

- `int`: $\lambda_i$: The Lagrange interpolation coefficient

**Example:**

```javascript
// shareIndices are hold the indices of the available shares, ordered
const lambdas = [];
for (const point of shareIndices) {
	const lambda_i = calculateLambda(point, shareIndices.length, group.ord);
	lambdas.push(lambda_i);
}

// Later, when the shares are acquired
// shares are the available shares, ordered wrt indices
for (const point of shares) {
	shares.push(lambdas.shift());
}

// Now, shamirCombineShares does not calculate lambdas within
const recons = shamirCombineShares(shares, group);
```

### <a name="genPol"></a>`genPol(constant, t, group)`

**Description:**

Constructs a degree $t-1$ semi-random polynomial.
All coefficients are exponents in the given group.

**Parameters:**

- `constant` (`BigIntegerAdapter`): Constant term
- `t` (`int`): Length of polynomial
- `group` (`PrimeGroup`): The group in which the operations are done
  
**Returns:**

- `[BigIntegerAdapter]`: An array of polynomial coefficients, representing a polynomial of degree $t-1$ with $a_0=$ `constant`, $a_i=$ random for all $0<i<t$.

**Example:**

*From [`shamirGenShares()`](#shamriGenShares)*
```javascript
const pnomial = genPol(secret, t, group);
```

### <a name="evalPol"></a>`evalPol(pol, x, group)`

**Description:**

Evaluates a polynomial at a point an a group.

**Parameters:**

- `pol` (`[BigIntegerAdapter]`): An array representing a polynomial
- `x` (`int`): The point on which to evaluate the polynomial
- `group` (`PrimeGroup`): The group in which the operations are done
  
**Returns:**

- `BigIntegerAdapter`: The polynomial evaluated at $x$

**Example:**

*From [`shamirGenShares()`](#shamriGenShares)*
```javascript
for (let i = 1; i <= n; i++) {
	shares.push([i, evalPol(pnomial, i, group)]);
}
```

### <a name="oprfMask"></a>`async oprfMask(secret, group)`

**Description:**

Creates the masked text to be sent to each SP (Storage provider).
Call this function once, and send alpha to each SP.
This returns a promise resolving to [$\rho$, $\alpha$], the SPs will respond with
$\beta_i = \alpha^{k_i}$ and $c_i$.
This function also returns $\rho$, which should be kept secret and only
be used as an input to the reconstructPassword function.

**Parameters:**

- `secret` (`string`): Client input to OPRF
- `group` (`PrimeGroup`): The group in which the operations are done
  
**Returns:**

- `Promise<[BigIntegerAdapter, BigIntegerAdapter]>`: `[$\rho$, $\alpha$]`: A pair corresponding to the random number $\rho$ and $alpha=\text{Hp}_x^\rho$

**Example:**

```javascript
// Client call
const group = new PrimeGroup();
const secret = "This is some very secret message to send over a secure channel.";
const [rho, alpha] = await oprfMask(secret, group);
```

### <a name="oprfChallenge"></a>`async oprfChallenge(alpha, k, group)`

**Description:**

Generates the challenge $\alpha^k$.

**Parameters:**

- `alpha` (`BigIntegerAdapter`): $\text{Hp}_x^\rho$ received from client
- `k` (`BigIntegerAdapter`): The OPRF key, secret value
- `group` (`PrimeGroup`): The group in which the operations are done
  
**Returns:**

- `Promise<BigIntegerAdapter>`:  $\beta = \alpha^k$

**Example:**

```javascript
// Server call
const key = group.randomExponent();
const beta = await oprfChallenge(alpha, key, group);
```


### <a name="oprfResponse"></a>`async oprfResponse(betas, rho, group)`

**Description:**

Calculates $\beta^{(\rho^{-1})}=\alpha^{(k\times\rho^{-1})}=\text{Hp}_x^{(\rho\times k\times (\rho^{-1}))} = \text{Hp}_x^k$.

If using t-OPRF, pass `betas` as an array. Otherwise, pass it ass a single `BigIntegerAdapter`

**Parameters:**

- `betas` (`[BigIntegerAdapter] | BigIntegerAdapter`): Either $\beta$ or an array of $\beta_i$s (on t-OPRF)
- `rho` (`BigIntegerAdapter`): The random number previously calculated on [`oprfMask()`](#oprfMask)
- `group` (`PrimeGroup`): The group in which the operations are done
  
**Returns:**

- `Promise<BigIntegerAdapter>`:  The output of OPRF: $\text{Hp}_x^k$

**Example:**

```javascript
// Client call
const resp = await oprfResponse(beta, rho, group);
```

### <a name="hash"></a>`async hash(str)`

**Description:**

Hashses a string using SHA-256, returns a promise resolving to the hash as a string.

**Parameters:**

- `str` (`string`): To digest into hash
  
**Returns:**

- `Promise<string>`:  SHA-256(str) in hexadecimal string form

**Example:**

```javascript
const hashed = await hash("Some text to hash");
```

### <a name="groupHash"></a>`async groupHash(str, group)`

**Description:**

Hashses a string to an element in the given group.
Returns a promise resolving to the hash as a hex string.
Note that this is not a fixed sized output.
I am not perfectly confident about the validity of this function.

**Parameters:**

- `str` (`string`): To digest into hash
- `group` (`PrimeGroup`): The group in which the operations are done
  
**Returns:**

- `Promise<string>`:  Hash(str) in hexadecimal string form

**Example:**

```javascript
const group = new PrimeGroup();
const hashed = await groupHash("Some text to hash", group);
```

# Security 

# Contributing

# License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Copying and Distribution Notice

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License or (at your option) any later version.

The code is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

For more details, see the [GNU General Public License](http://www.gnu.org/licenses/).

# Acknowledgements

This library was implemented as an intership project under the supervision of Prof. Alptekin Küpçü and Devriş İşler.
