import crypt from './crypt';

export default class CustomKeys {
  constructor(authInfo) {
    this.authInfo = authInfo;
    this.username = authInfo.username;
    this.id = null;
    this.crypt = null;      // login
    this.unlock = null;     // unlock
  }

  static deserialize(obj) {
    const customKeys = new CustomKeys(obj.authInfo);
    customKeys.id = obj.id;
    customKeys.crypt = obj.crypt;
    customKeys.unlock = obj.unlock;
    return customKeys;
  }

  setUsername(username) {
    if (this.username !== username) {
      this.id = null;
      this.crypt = null;
      this.unlock = null;
      this.username = username;
      this.authInfo.username = username;
    }
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
   * deriveUnlockKey
   */
  deriveUnlockKey(password) {
    const normalizedUsername = this.authInfo.username.toLowerCase().replace(/-/g, '');

    // derive unlock key
    return crypt.derive(this.authInfo.pakdf, 'unlock', normalizedUsername, password)
      .then((keys) => {
        console.log('deriveUnlockKey: derived new');
        this.unlock = keys.unlock;
        return Promise.resolve(this);
      });
  }

  deriveKeys(password) {
    return this.deriveLoginKeys(password)
      .then(() => this.deriveUnlockKey(password));
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
}
