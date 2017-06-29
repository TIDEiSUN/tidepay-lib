import extend from 'extend';
import sjcl from './sjcl';
import jacobi from './sjcl-custom/sjcl-jacobi';
import Utils from '../common/utils';

const SJCL_PARANOIA_256_BITS = 6;
const cryptConfig = {
  cipher : 'aes',
  mode   : 'ccm',
  ts     : 64,   // tag length
  ks     : 256,  // key size
  iter   : 1000  // iterations (key derivation)
};

/**
 * Full domain hash based on SHA512
 */

function fdh(data, bytelen) {
  var bitlen = bytelen << 3;

  if (typeof data === 'string') {
    data = sjcl.codec.utf8String.toBits(data);
  }

  // Add hashing rounds until we exceed desired length in bits
  var counter = 0, output = [];

  while (sjcl.bitArray.bitLength(output) < bitlen) {
    var hash = sjcl.hash.sha512.hash(sjcl.bitArray.concat([counter], data));
    output = sjcl.bitArray.concat(output, hash);
    counter++;
  }

  // Truncate to desired length
  output = sjcl.bitArray.clamp(output, bitlen);

  return output;
};

/**
 * This is a function to derive different hashes from the same key. 
 * Each hash is derived as HMAC-SHA512HALF(key, token).
 *
 * @param {string} key
 * @param {string} hash
 */

function keyHash(key, token) {
  var hmac = new sjcl.misc.hmac(key, sjcl.hash.sha512);
  return sjcl.codec.hex.fromBits(sjcl.bitArray.bitSlice(hmac.encrypt(token), 0, 256));
};

/**
 * add entropy at each call to get random words
 * @param {number} nWords
 */
function randomWords (nWords) {
  return sjcl.random.randomWords(nWords, SJCL_PARANOIA_256_BITS);
}

function setFirstBit (bigNumber) {
  bigNumber.limbs[0] |= 1;
  return bigNumber;
}

/****** exposed functions ******/

const Crypt = {

/**
 * KEY DERIVATION FUNCTION
 *
 * This service takes care of the key derivation, i.e. converting low-entropy
 * secret into higher entropy secret via either computationally expensive
 * processes or peer-assisted key derivation (PAKDF).
 *
 * @param {object}    opts
 * @param {string}    purpose - Key type/purpose
 * @param {string}    username
 * @param {string}    secret - Also known as passphrase/password
 * @param {function}  fn
 */

  derive(opts, purpose, username, secret) {
    var tokens;

    if (purpose === 'login') {
      tokens = ['id', 'crypt'];
    } else if (purpose === 'unlock') {
      tokens = ['secretId', 'unlock'];
    } else {
      throw new Error('Invalid purpose');
    }

    var iExponent = new sjcl.bn(String(opts.exponent));
    var iModulus  = new sjcl.bn(String(opts.modulus));
    var iAlpha    = new sjcl.bn(String(opts.alpha));

    var publicInfo = [ 'PAKDF_1_0_0', opts.host.length, opts.host, username.length, username, purpose.length, purpose ].join(':') + ':';
    var publicSize = Math.ceil(Math.min((7 + iModulus.bitLength()) >>> 3, 256) / 8);
    var publicHash = fdh(publicInfo, publicSize);
    var publicHex  = sjcl.codec.hex.fromBits(publicHash);
    var iPublic    = setFirstBit(new sjcl.bn(String(publicHex)));
    var secretInfo = [ publicInfo, secret.length, secret ].join(':') + ':';
    var secretSize = (7 + iModulus.bitLength()) >>> 3;
    var secretHash = fdh(secretInfo, secretSize);
    var secretHex  = sjcl.codec.hex.fromBits(secretHash);
    var iSecret    = new sjcl.bn(String(secretHex)).mod(iModulus);

    if (jacobi(iSecret, iModulus) !== 1) {
      iSecret = iSecret.mul(iAlpha).mod(iModulus);
    }

    var iRandom;

    for (;;) {
      iRandom = sjcl.bn.random(iModulus, SJCL_PARANOIA_256_BITS);
      if (jacobi(iRandom, iModulus) === 1) {
        break;
      }
    }

    var iBlind   = iRandom.powermod(iPublic.mul(iExponent), iModulus);
    var iSignreq = iSecret.mulmod(iBlind, iModulus);
    var signreq  = sjcl.codec.hex.fromBits(iSignreq.toBits());

    return fetch(opts.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify( { info: publicInfo, signreq: signreq } ),
    })
    .then((resp) => {
      if (resp.status !== 200) {
        return Promise.reject(new Error(`PAKDF server returns ${resp.statusText}` ));
      }
      
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      var iSignres = new sjcl.bn(String(data.signres));
      var iRandomInv = iRandom.inverseMod(iModulus);
      var iSigned    = iSignres.mulmod(iRandomInv, iModulus);
      var key        = iSigned.toBits();
      var result     = { };

      tokens.forEach(function(token) {
        result[token] = keyHash(key, token);
      });
      
      return Promise.resolve(result);
    })
    .catch((err) => {
      console.error('derive:', err);
      return Promise.reject(new Error('Could not query PAKDF server ' + opts.host));
    })
  },

/**
 * Encrypt data
 *
 * @param {string} key
 * @param {string} data
 */

  encrypt(key, data) {
    key = sjcl.codec.hex.toBits(key);

    var opts = extend(true, {}, cryptConfig);

    var encryptedObj = JSON.parse(sjcl.encrypt(key, data, opts));
    var version = [sjcl.bitArray.partial(8, 0)];
    var initVector = sjcl.codec.base64.toBits(encryptedObj.iv);
    var ciphertext = sjcl.codec.base64.toBits(encryptedObj.ct);

    var encryptedBits = sjcl.bitArray.concat(version, initVector);
    encryptedBits = sjcl.bitArray.concat(encryptedBits, ciphertext);

    return sjcl.codec.base64.fromBits(encryptedBits);
  },

/**
 * Decrypt data
 *
 * @param {string} key
 * @param {string} data
 */

  decrypt(key, data) {
    
    key = sjcl.codec.hex.toBits(key);
    var encryptedBits = sjcl.codec.base64.toBits(data);

    var version = sjcl.bitArray.extract(encryptedBits, 0, 8);

    if (version !== 0) {
      throw new Error('Unsupported encryption version: '+version);
    }

    var encrypted = extend(true, {}, cryptConfig, {
      iv: sjcl.codec.base64.fromBits(sjcl.bitArray.bitSlice(encryptedBits, 8, 8+128)),
      ct: sjcl.codec.base64.fromBits(sjcl.bitArray.bitSlice(encryptedBits, 8+128))
    });

    return sjcl.decrypt(key, JSON.stringify(encrypted));
  },

/**
 * Create an encryption key
 *
 * @param {integer} nWords - number of words
 */

  createSecret(nWords) {
    return sjcl.codec.hex.fromBits(randomWords(nWords));
  },

/**
 * Hash data using SHA-512.
 *
 * @param {string|bitArray} data
 * @return {string} Hash of the data
 */

  hashSha512(data) {
    // XXX Should return a UInt512
    return sjcl.codec.hex.fromBits(sjcl.hash.sha512.hash(data)); 
  },

/**
 * Sign a data string with a secret key
 *
 * @param {string} secret
 * @param {string} data
 */

  signString(secret, data) {
    const hmac = new sjcl.misc.hmac(sjcl.codec.hex.toBits(secret), sjcl.hash.sha512);
    return sjcl.codec.hex.fromBits(hmac.mac(data));
  },

/**
 * Create an an account recovery key
 *
 * @param {string} secret
 */

  deriveRecoveryEncryptionKeyFromSecret(secret) {
    const hash = sjcl.hash.sha512.hash(sjcl.codec.utf8String.toBits(secret));
    const seed = sjcl.bitArray.bitSlice(hash, 0, 128);
    const hmac = new sjcl.misc.hmac(seed, sjcl.hash.sha512);
    let key = hmac.mac('ripple/hmac/recovery_encryption_key/v1');
    key = sjcl.bitArray.bitSlice(key, 0, 256);
    return sjcl.codec.hex.fromBits(key);
  },

/**
 * Convert base64 encoded data into base64url encoded data.
 *
 * @param {String} base64 Data
 */

  base64ToBase64Url(encodedData) {
    return encodedData.replace(/\+/g, '-').replace(/\//g, '_').replace(/[=]+$/, '');
  },

/**
 * Convert base64url encoded data into base64 encoded data.
 *
 * @param {String} base64 Data
 */

  base64UrlToBase64(encodedData) {
    encodedData = encodedData.replace(/-/g, '+').replace(/_/g, '/');

    while (encodedData.length % 4) {
      encodedData += '=';
    }

    return encodedData;
  },

/**
 * base64 to UTF8
 */

  decodeBase64(data) {
    return sjcl.codec.utf8String.fromBits(sjcl.codec.base64.toBits(data));
  },

};

export default Crypt;
