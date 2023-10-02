# browser-crypto-lib by Crypto-KU

[![NPM version](https://img.shields.io/npm/v/browser-crypto-lib.svg)](https://www.npmjs.com/package/browser-crypto-lib)
[![Build Status](https://img.shields.io/travis/CRYPTO-KU/browser-crypto-lib.svg)](https://travis-ci.org/CRYPTO-KU/browser-crypto-lib)

- Note: The above links are not yet initialized.

browser-crypto-lib is a lightweight and modular JavaScript library providing cryptographic utilities in the browser and Node.js environments. It focuses on ease of use and performance testing. It serves as a wrapper for other libraries when applicable, and implements some other functionality.

browser-crypto-lib should only be used for proof of concept and research applications. The code must be reviewed by security experts for security reliant applications.

browser-crypto-lib makes heavy use of async/await calls; so, a tool such as [Browserify](https://browserify.org) should be used for browser compatibility. This is a straightforward extra step that makes the process of coding for browsers easier.

The library is not yet complete as some functionalities are still being implemented and the code is being refactored.

## Features
- Easy to use cryptographic functions
- Cryptographic Hashing
- Digital Signatures
- Symmetric and Asymmetric Encryption
- Shamir Secret Sharing
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
- `signature` (`ArrayBuffer`) Signature generated with [sign()](#sign)
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
- `Promise<CryptoKeyPair>`: (privKey, pubKey)

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
- `Promise<[ArrayBuffer, Uint8Array, Uint8Array]>`: [ciphertext, counter, salt]

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
- `ciphertext` (`ArrayBuffer`): Ciphertext generated by [encrypt()](#encrypt)
- `password` (`string`): User input to derive the encryption key
- `hashFunction` (`string`): Used for key derivation (PBKDF2), i.e., "SHA-256"
- `iterations` (`int`): Used for key derivation (PBKDF2)
- `salt` (`Uint8Array`): Used for key derivation (PBKDF2)
- `counter` (`Uint8Array`): Counter generated by [encrypt()](#encrypt)

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
Wrapper for the importKey function of the Subtle interface of WebCrypto APIç
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
Generates a responds to the challenge, proving knowledge of x.
Note that X = g^x is normally assumed to be known, because the
public key is (g^x, group). For the sake of simplicity, it is
returned here; as this has little effect on performance numbers.
Note: Public key is calculated here.

**Parameters:**
- `x` (`BigIntegerAdapter`): The secret value to be proven, an exponent in the group
- `c` (`BigIntegerAdapter`): The challenge sent by the challenger
- `group` (`PrimeGroup`): The group in which the operations are done
**Returns:**
- `[BigIntegerAdapter, BigIntegerAdapter, BigIntegerAdapter]`: [X, Y, z]: X = g^x the public key, Y= g^random, z = y*x^c the response.

**Example:**

```javascript
const group = new PrimeGroup();
const secret = group.randomExponent();
const resp = schnorrResponse(secret, c, group);
```

### <a name="schnorrVerify"></a>`schnorrVerify(X, Y, z, c, group)`

**Description:**
Verifies that the prover has the private key corresponding to the public key X.
**Parameters:**
- `X` (`BigIntegerAdapter`): The public key
- `Y` (`BigIntegerAdapter`): First part of the response
- `z` (`BigIntegerAdapter`): First part of the response
- `c` (`BigIntegerAdapter`): The challenge
- `group` (`PrimeGroup`): The group in which the operations are done
**Returns:**
- `bool`: g^z == Y*X^c (in group)

**Example:**

```javascript
const group = new PrimeGroup();
const secret = group.randomExponent();
const resp = schnorrResponse(secret, c, group);
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