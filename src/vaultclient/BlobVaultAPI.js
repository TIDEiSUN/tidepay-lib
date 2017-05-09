import BlobAPI from './blob';
import AuthInfo from './authinfo';
import crypt from './crypt';
import Utils from './utils';
import Errors from './Errors';

export default class BlobVaultAPI {
  constructor(isunpayrpcURL) {
    this.isunpayrpcURL = isunpayrpcURL;
    this.infos = {};
  }
  /**
   * Get auth info for a given username
   *
   * @param {string}    username
   */

  getByUsername(username) {
    return AuthInfo.getAuthInfo(this.isunpayrpcURL, { username });
  }

  getByEmail(email) {
    return AuthInfo.getAuthInfo(this.isunpayrpcURL, { email });
  }

  getByAddress(address) {
    return AuthInfo.getAuthInfo(this.isunpayrpcURL, { address });
  }

  /**
   * getAuthInfo
   * gets auth info for a username. returns authinfo
   * even if user does not exists (with exist set to false)
   * @param {string} username
   * @param {function} callback
   */
  getAuthInfo(username) {
    return this.getByUsername(username).then((authInfo) => {
      if (authInfo.version !== 3) {
        return Promise.reject(new Error('This wallet is incompatible with this version of the vault-client.'));
      }

      if (!authInfo.pakdf) {
        return Promise.reject(new Error('No settings for PAKDF in auth packet.'));
      }

      if (typeof authInfo.blobvault !== 'string') {
        return Promise.reject(new Error('No blobvault specified in the authinfo.'));
      }

      return Promise.resolve(authInfo);
    });
  }

  /**
   * Check blobvault for existance of username
   *
   * @param {string}    username
   * @param {function}  fn - Callback function
   */

  exists(username) {
    return this.getByUsername(username)
      .then(authInfo => Promise.resolve(!!authInfo.exists));
  }

  /**
   * Check blobvault for existance of address
   *
   * @param {string}    address
   * @param {function}  fn - Callback function
   */

  addressExists(address) {
    return this.getByAddress(address)
      .then(authInfo => Promise.resolve(!!authInfo.exists));
  }

  /**
   * Decrypt the secret key using a username and password
   *
   * @param {string}    username
   * @param {string}    password
   * @param {string}    encryptSecret
   */

  unlock(encryptSecret, customKeys) {
    if (!customKeys.authInfo.exists) {
      return Promise.reject(new Error('User does not exists.'));
    }

    return customKeys.deriveUnlockKey()
      .then(() => {
        try {
          const secret = crypt.decrypt(customKeys.unlock, encryptSecret);
          return Promise.resolve({ customKeys, secret });
        } catch (error) {
          return Promise.reject(error);
        }
      });
  }

  /**
   * updateBlob
   * @param {object} options
   * @param {string} options.username
   * @param {string} options.masterkey
   * @param {object} options.blob
   */

  updateBlob(options) {
    const customKeys = options.customKeys;
    const authInfo = customKeys.authInfo;

    if (!authInfo.exists) {
      return Promise.reject(new Error('User does not exists.'));
    }
    if (!authInfo.emailVerified) {
      return Promise.reject(new Error('Account has not been verified.'));
    }

    return customKeys.deriveKeys()
      .then(() => {
        options.keys = customKeys;
        return BlobAPI.updateBlob(options);
      });
  }

  /**
   * changePassword
   * @param {object} options
   * @param {string} options.username
   * @param {string} options.password
   * @param {string} options.masterkey
   * @param {object} options.blob
   */

  changePassword(options) {
    const password = String(options.password).trim();

    const customKeys = options.customKeys;
    const authInfo = customKeys.authInfo;

    if (!authInfo.exists) {
      return Promise.reject(new Error('User does not exists.'));
    }
    if (!authInfo.emailVerified) {
      return Promise.reject(new Error('Account has not been verified.'));
    }

    customKeys.setPassword(password);

    return customKeys.deriveKeys()
      .then(() => {
        options.keys = customKeys;
        return BlobAPI.updateKeys(options);
      });
  }

  /**
   * Activate a tidepay account
   */

  authActivateAccount(customKeys, email, authToken, blobData, createAccountToken) {
    const createAccount = () => {
      return fetch(`${this.isunpayrpcURL}/account/${createAccountToken}`, { method: 'POST' })
      .then((resp) => {
        return Utils.handleFetchResponse(resp);
      })
      .then((data) => {
        return Promise.resolve(data.account);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'authActivateAccount');
      })
    };

    return createAccount()
      .then((account) => {
        const options = {
          keys: customKeys,
          email,
          masterkey: account.secret,
          address: account.address,
          username: customKeys.username,
          url: customKeys.authInfo.blobvault,
          authToken,
          blobData,
        };
        const activatePromise = BlobAPI.authActivateAccount(options);
        return Promise.all([account, activatePromise]);
      })
      .then(([account, resp]) => {
        const { secret } = account;
        return Promise.resolve({ ...resp, secret });
      });
  }

  authVerifyAccountEmailToken(username, email, emailToken, authToken) {
    return this.getAuthInfo(username)
      .then((authInfo) => {
        const options = {
          email,
          emailToken,
          username,
          url: authInfo.blobvault,
          authToken,
        };
        return BlobAPI.authVerifyAccountEmailToken(options);
      });
  }

  /**
   * Register a new user and save to the blob vault
   *
   * @param {object} options
   * @param {string} options.username
   * @param {string} options.password
   * @param {string} options.email
   * @param {string} options.activateLink
   * @param {string} options.domain
   */

  authRegister(options) {
    const username = String(options.username).trim();
    const password = String(options.password).trim();

    if (!this.validateEmail(options.email).valid) {
      return Promise.reject(new Error('Invalid email address'));
    }

    if (!this.validateUsername(username).valid) {
      return Promise.reject(new Error('Invalid username'));
    }

    const create = (authInfo, customKeys) => {
      let params = {
        url: authInfo.blobvault,
        id: customKeys.id,
        crypt: customKeys.crypt,
        unlock: customKeys.unlock,
        username: username,
        email: options.email,
        activateLink: options.activateLink,
        domain: options.domain,
      };

      return BlobAPI.authCreate(params)
        .then((blob) => {
          return Promise.resolve({
            blob: blob,
            customKeys: customKeys,
            username: username,
          });
        });
    };

    return this.getAuthInfo(username)
      .then((authInfo) => {
        const customKeys = new CustomKeys(authInfo, password);
        return customKeys.deriveKeys();
      })
      .then((customKeys) => create(customKeys.authInfo, customKeys));
  }

  /**
   * validateUsername
   * check username for validity
   */

  // TODO validate username when change username
  validateUsername(username) {
    username = String(username).trim();
    var result = {
      valid: false,
      reason: '',
    };

    // FIXME fix validate regex
    if (username.length < 8) {
      result.reason = 'tooshort';
    } else if (username.length > 32) {
      result.reason = 'toolong';
    } else if (!/^[a-zA-Z0-9\-]+$/.exec(username)) {
      result.reason = 'charset';
    } else if (/^-/.exec(username)) {
      result.reason = 'starthyphen';
    } else if (/-$/.exec(username)) {
      result.reason = 'endhyphen';
    } else if (/--/.exec(username)) {
      result.reason = 'multhyphen';
    } else {
      result.valid = true;
    }

    return result;
  }

  /**
   * validateEmail
   * check email adderss for validity
   */

  validateEmail(email) {
    email = String(email).trim();
    var result = {
      valid: false,
      reason: '',
    };

    var emailRE = new RegExp('^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$');
    if (!emailRE.exec(email)) {
      result.reason = 'invalidemail';
    } else {
      result.valid = true;
    }

    return result;
  }

  /**
   * generateDeviceID
   * create a new random device ID for 2FA
   */
  generateDeviceID() {
    return crypt.createSecret(4);
  }
}

// TODO use extend ?

/*** pass thru some blob client function ***/

BlobVaultAPI.prototype.deleteBlob = BlobAPI.deleteBlob;

BlobVaultAPI.prototype.blockAccount = BlobAPI.blockAccount;

BlobVaultAPI.prototype.addBankAccount = BlobAPI.addBankAccount;

BlobVaultAPI.prototype.deleteBankAccount = BlobAPI.deleteBankAccount;

BlobVaultAPI.prototype.handleRecovery = BlobAPI.handleRecovery;

BlobVaultAPI.prototype.authUnblockAccount = BlobAPI.authUnblockAccount;

BlobVaultAPI.prototype.authRecoverAccount = BlobAPI.authRecoverAccount;

BlobVaultAPI.prototype.authRequestUpdateEmail = BlobAPI.authRequestUpdateEmail;

BlobVaultAPI.prototype.authVerifyUpdateEmail = BlobAPI.authVerifyUpdateEmail;

BlobVaultAPI.prototype.authRequestUpdatePhone = BlobAPI.authRequestUpdatePhone;

BlobVaultAPI.prototype.authVerifyUpdatePhone = BlobAPI.authVerifyUpdatePhone;

BlobVaultAPI.prototype.authLogin = BlobAPI.authLogin;

BlobVaultAPI.prototype.getBlob = BlobAPI.getBlob;