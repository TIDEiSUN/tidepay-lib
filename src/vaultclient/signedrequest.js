import extend from 'extend';
import querystring from 'querystring';
import parser from 'url';
import Crypt from './crypt';
import binary from '../tidepay/tidepay-binary-codec';
import keyPairs from '../tidepay/tidepay-keypairs';

// from npm extend
function isPlainObject(obj) {
  const hasOwn = Object.prototype.hasOwnProperty;
  const toString = Object.prototype.toString;

  if (!obj || toString.call(obj) !== '[object Object]' || obj.nodeType || obj.setInterval) {
    return false;
  }

  const has_own_constructor = hasOwn.call(obj, 'constructor');
  const has_is_property_of_method = hasOwn.call(obj.constructor.prototype, 'isPrototypeOf');
  // Not own constructor property must be Object
  if (obj.constructor && !has_own_constructor && !has_is_property_of_method) {
    return false;
  }

  // Own properties are enumerated firstly, so to speed up,
  // if last one is own, then all properties are own.
  let key;
  for (key in obj) {}

  return key === undefined || hasOwn.call(obj, key);
}

// prepare for signing
function copyObjectWithSortedKeys(object) {
  if (isPlainObject(object)) {
    const newObj = {};
    const keysSorted = Object.keys(object).sort();
    let key;
    for (let i in keysSorted) {
      key = keysSorted[i];
      if (Object.prototype.hasOwnProperty.call(object, key)) {
        const obj = copyObjectWithSortedKeys(object[key]);
        if (obj !== undefined) {
          newObj[key] = obj;
        }
      }
    }
    return newObj;
  } else if (Array.isArray(object)) {
    return object.map(copyObjectWithSortedKeys);
  } else if (object instanceof File) {
    // TODO temp skip file type
    return undefined;
  } else if (object instanceof FormData) {
    const convertedObject = {};
    for (const [key, value] of object.entries()) {
      convertedObject[key] = value;
    }
    return copyObjectWithSortedKeys(convertedObject);
  } else {
    return object;
  }
}

const dateAsIso8601 = (function () {
  function pad(n) {
    return (n < 0 || n > 9 ? '' : '0') + n;
  }

  return function dateAsIso8601() {
    const date = new Date();
    return date.getUTCFullYear() + "-" +
      pad(date.getUTCMonth()     + 1)  + "-" +
      pad(date.getUTCDate())     + "T" +
      pad(date.getUTCHours())    + ":" +
      pad(date.getUTCMinutes())  + ":" +
      pad(date.getUTCSeconds())  + ".000Z";
  };
}());

const MAGIC_BYTES = 'Tidepay Signed Message:\n';

function signMessage(message, secret) {
  const keypair = keyPairs.deriveKeypair(secret);
  const messageHex = binary.encodeForSigning({ message: MAGIC_BYTES + message });
  const signature = keyPairs.sign(messageHex, keypair.privateKey);
  return { signature, publicKey: keypair.publicKey };
}

export default class SignedRequest {
  constructor(config) {
    // XXX Constructor should be generalized and constructing from an Angular.js
    //     $http config should be a SignedRequest.from... utility method.
    this.config = extend(true, {}, config);
    if (!this.config.data) this.config.data = {};
  }

/**
 * Create a string from request parameters that
 * will be used to sign a request
 * @param {Object} parsed - parsed url
 * @param {Object} date
 * @param {Object} mechanism - type of signing
 */
  getStringToSign(parsed, date, mechanism) {
    // XXX This method doesn't handle signing GET requests correctly. The data
    //     field will be merged into the search string, not the request body.

    // Sort the properties of the JSON object into canonical form
    const canonicalData = JSON.stringify(copyObjectWithSortedKeys(this.config.data));

    // Canonical request using Amazon's v4 signature format
    // See: http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    const canonicalRequest = [
      this.config.method || 'GET',
      parsed.pathname || '',
      parsed.search || '',
      // XXX Headers signing not supported
      '',
      '',
      Crypt.hashSha512(canonicalData).toLowerCase(),
    ].join('\n');

    // String to sign inspired by Amazon's v4 signature format
    // See: http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
    //
    // We don't have a credential scope, so we skip it.
    //
    // But that modifies the format, so the format ID is RIPPLE1, instead of AWS4.
    return [
      mechanism,
      date,
      Crypt.hashSha512(canonicalRequest).toLowerCase(),
    ].join('\n');
  }

/**
 * HMAC signed request
 * @param {Object} config
 * @param {Object} auth_secret
 * @param {Object} blob_id
 */
  signHmac(auth_secret, blob_id) {
    const config = extend(true, {}, this.config);

    // Parse URL
    const parsed        = parser.parse(config.url);
    const date          = dateAsIso8601();
    const signatureType = 'RIPPLE1-HMAC-SHA512';
    const stringToSign  = this.getStringToSign(parsed, date, signatureType);
    const signature     = Crypt.signString(auth_secret, stringToSign);

    const query = querystring.stringify({
      signature: Crypt.base64ToBase64Url(signature),
      signature_date: date,
      signature_blob_id: blob_id,
      signature_type: signatureType,
    });

    config.url += (parsed.search ? '&' : '?') + query;
    return config;
  }

/**
 * Asymmetric signed request
 * @param {Object} config
 * @param {Object} secretKey
 * @param {Object} account
 * @param {Object} blob_id
 */
  signAsymmetric(secretKey, account, blob_id) {
    const config = extend(true, {}, this.config);

    // Parse URL
    const parsed        = parser.parse(config.url);
    const date          = dateAsIso8601();
    const signatureType = 'RIPPLE1-ECDSA-SHA512';
    const stringToSign  = this.getStringToSign(parsed, date, signatureType);
    const { signature, publicKey } = signMessage(stringToSign, secretKey);

    const query = querystring.stringify({
      signature: Crypt.base64ToBase64Url(signature),
      signature_date: date,
      signature_blob_id: blob_id,
      signature_account: account,
      signature_public_key: publicKey,
      signature_type: signatureType,
    });

    config.url += (parsed.search ? '&' : '?') + query;

    return config;
  }

}
