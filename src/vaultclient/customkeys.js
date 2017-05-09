import crypt from './crypt';

export default class CustomKeys {
  constructor(authInfo, password) {
    this.authInfo = authInfo;
    this.username = authInfo.username;
    this.password = password;
    this.id = null;
    this.crypt = null;      // login
    this.unlock = null;     // unlock
  }

  static deserialize(obj) {
    const customKeys = new CustomKeys(obj.authInfo, obj.password);
    customKeys.id = obj.id;
    customKeys.crypt = obj.crypt;
    customKeys.unlock = obj.unlock;
    return customKeys;
  }

  setPassword(password) {
    if (this.password !== password) {
      this.id = null;
      this.crypt = null;
      this.unlock = null;
      this.password = password;
    }
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
  deriveLoginKeys() {
    const normalizedUsername = this.authInfo.username.toLowerCase().replace(/-/g, '');

    if (this.id && this.crypt) {
      console.log('deriveLoginKeys: use existing');
      return Promise.resolve(this);
    }

    // derive login keys
    return crypt.derive(this.authInfo.pakdf, 'login', normalizedUsername, this.password)
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
  deriveUnlockKey() {
    const normalizedUsername = this.authInfo.username.toLowerCase().replace(/-/g, '');

    if (this.unlock) {
      console.log('deriveUnlockKey: use existing');
      return Promise.resolve(this);
    }

    // derive unlock key
    return crypt.derive(this.authInfo.pakdf, 'unlock', normalizedUsername, this.password)
      .then((keys) => {
        console.log('deriveUnlockKey: derived new');
        this.unlock = keys.unlock;
        return Promise.resolve(this);
      });
  }

  deriveKeys() {
    return this.deriveLoginKeys()
      .then(() => this.deriveUnlockKey());
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
      .then((keys) => Promise.resolve({ correct: this.id === keys.id }))
      .catch((err) => Promise.reject(err));
  }
}
