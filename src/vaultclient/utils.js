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
};
