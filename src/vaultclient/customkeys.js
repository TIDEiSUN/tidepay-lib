import crypt from './crypt';

export default class CustomKeys {
  constructor(authInfo) {
    this.authInfo = authInfo;
    this.username = authInfo.username;
    this.id = null;         // login
    this.crypt = null;      // login
    this.secretId = null;   // unlock
    this.unlock = null;     // unlock
  }

  static deserialize(obj) {
    const customKeys = new CustomKeys(obj.authInfo);
    customKeys.id = obj.id;
    customKeys.crypt = obj.crypt;
    customKeys.secretId = obj.secretId;
    customKeys.unlock = obj.unlock;
    return customKeys;
  }

  static clone(obj) {
    return this.deserialize(obj);
  }

  static createUnlockSecret() {
    return crypt.createSecret(4);
  }

  /**
   * deriveLoginKeys
   */
  deriveLoginKeys(password) {
    const normalizedUsername = this.authInfo.username.toLowerCase().replace(/-/g, '');

    // derive login keys
    return crypt.derive(this.authInfo.pakdf, 'login', normalizedUsername, password)
      .then((keys) => {
        console.log('deriveLoginKeys: derived new');
        this.id = keys.id;
        this.crypt = keys.crypt;
        return Promise.resolve(this);
      });
  }

  /**
   * deriveUnlockKeys
   */
  deriveUnlockKeys(unlockSecret, paymentPin = '') {
    const normalizedUnlockSecret = unlockSecret.toLowerCase();

    // derive unlock key
    return crypt.derive(this.authInfo.pakdf, 'unlock', normalizedUnlockSecret, paymentPin)
      .then((keys) => {
        console.log('deriveUnlockKeys: derived new');
        if (paymentPin) {
          this.secretId = keys.secretId;
        }
        this.unlock = keys.unlock;
        return Promise.resolve(this);
      });
  }

  /**
   * Check whether the given password is correct
   */
  isPasswordCorrect(candidatePassword) {
    if (this.id === null) {
      return Promise.reject(new Error('User has not logged in'));
    }
    const normalizedUsername = this.authInfo.username.toLowerCase().replace(/-/g, '');
    return crypt.derive(this.authInfo.pakdf, 'login', normalizedUsername, candidatePassword)
      .then(keys => Promise.resolve({ correct: this.id === keys.id }));
  }

  /**
   * Check whether the given payment pin is correct
   */
  isPaymentPinCorrect(unlockSecret, candidatePaymentPin) {
    if (this.secretId === null) {
      return Promise.reject(new Error('Secret has not unlocked'));
    }
    const normalizedUnlockSecret = unlockSecret.toLowerCase();
    return crypt.derive(this.authInfo.pakdf, 'unlock', normalizedUnlockSecret, candidatePaymentPin)
      .then(keys => Promise.resolve({ correct: this.secretId === keys.secretId }));
  }
}
