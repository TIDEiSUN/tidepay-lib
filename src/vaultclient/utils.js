import crypto from 'crypto';
import sjcl from './sjcl';

// see https://github.com/speakeasyjs/speakeasy/blob/master/index.js
function generateSecretASCII(length, symbols) {
  var bytes = crypto.randomBytes(length || 32);
  var set = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz';
  if (symbols) {
    set += '!@#$%^&*()<>?/[]{},.:;';
  }

  var output = '';
  for (var i = 0, l = bytes.length; i < l; i++) {
    output += set[Math.floor(bytes[i] / 255.0 * (set.length - 1))];
  }
  return output;
}

export default {
  createRecoveryKey(email) {
    return `@@@RecoveR!!!!!${email}!!`;
  },

  createSecretRecoveryKey(phone, unlockSecret) {
    return `@@@SecretRecoveR!!!!!(${phone.countryCode})${phone.phoneNumber}_${unlockSecret}!!`;
  },

  maskphone(phone) {
    if (!phone) {
      return '';
    }
    const first = phone.substr(0, phone.length - 4).replace(/\d/g, '*');
    const last = phone.substr(-4);
    return first.concat(last);
  },

  checkPhoneVerified(accountLevel) {
    return accountLevel === 'B' || accountLevel === 'A';
  },

  createHashedBankAccount(bankAccountInfo) {
    const infoStr = JSON.stringify(bankAccountInfo);
    const hashedBitArray = sjcl.hash.sha256.hash(infoStr);
    return sjcl.codec.hex.fromBits(hashedBitArray);
  },

  generateGAuthSecret() {
    const key = generateSecretASCII(20, true);
    const hex = Buffer(key, 'ascii').toString('hex');
    const hexBits = sjcl.codec.hex.toBits(hex);
    const base32 = sjcl.codec.base32.fromBits(hexBits);
    return base32.replace(/=/g, '');
  },
};
