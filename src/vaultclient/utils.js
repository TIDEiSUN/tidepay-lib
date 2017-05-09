import sjcl from './sjcl';
import Errors from './Errors';

export default {
  createRecoveryKey(email) {
    return `@@@RecoveR!!!!!${email}!!`;
  },

  createHashedPhone(phone) {
    const phoneStr = `(${phone.countryCode})${phone.phoneNumber}`;
    const hashedBitArray = sjcl.hash.sha256.hash(phoneStr);
    return sjcl.codec.hex.fromBits(hashedBitArray);
  },

  createHashedBankAccount(bankAccountInfo) {
    const infoStr = JSON.stringify(bankAccountInfo);
    const hashedBitArray = sjcl.hash.sha256.hash(infoStr);
    return sjcl.codec.hex.fromBits(hashedBitArray);
  },

  maskphone(phone) {
    if (!phone) {
      return '';
    }
    const first = phone.substr(0, phone.length - 4).replace(/\d/g,'*');
    const last = phone.substr(-4);
    return first.concat(last);
  },

  checkPhoneVerified(accountLevel) {
    return accountLevel === 'B' || accountLevel === 'A';
  },

  makeFetchRequestOptions(config) {
    const options = {
      method : config.method,
      headers: {
        'Content-Type': 'application/json',
      },
      body   : JSON.stringify(config.data),
    };
    return options;
  },

  handleFetchResponse(resp) {
    if (resp.status < 200 || resp.status > 299) {
      const contentType = resp.headers.get('content-type');
      if (contentType && contentType.indexOf('application/json') !== -1) {
        return resp.json().then((err) => {
          const { code, message, ...info } = err;
          return Promise.reject(new Errors.FetchError(resp.status, message, code, info));
        });
      }
      return Promise.reject(new Errors.FetchError(resp.status, resp.statusText));
    }
    return resp.json();
  },

  handleFetchError(err, message) {
    console.error(`${message}:`, err);
    return Promise.reject(err);
  },
};
