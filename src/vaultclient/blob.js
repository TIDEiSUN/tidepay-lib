import crypt from './crypt';
import SignedRequest from './signedrequest';
import BlobObj from './BlobObj';
import Utils from './utils';

/**
 * Get ripple name for a given address
 */

export default {
  getBlob(url, token) {
    const config = {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      },
    };
    return fetch(`${url}/v1/blob`, config)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    }) 
    .catch((err) => {
      return Utils.handleFetchError(err, 'getBlob');
    });
  },

  authLogin(opts) {
    const config = Utils.makeFetchRequestOptions( { method : 'POST', data : opts.data } );
    const url = `${opts.url}/v1/user/auth/login`;
    return fetch(url, config)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    }) 
    .catch((err) => {
      return Utils.handleFetchError(err, 'authLogin');
    });
  },

  authUnblockAccount(opts) {
    const config = Utils.makeFetchRequestOptions( { method : 'POST', data : opts.data } );
    const url = `${opts.url}/v1/user/auth/unblock`;
    return fetch(url, config)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    }) 
    .catch((err) => {
      return Utils.handleFetchError(err, 'authUnblockAccount');
    });
  },

  authRecoverAccount(opts) {
    const config = Utils.makeFetchRequestOptions( { method : 'POST', data : opts.data } );
    const url = `${opts.url}/v1/user/auth/recover`;
    return fetch(url, config)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    }) 
    .catch((err) => {
      return Utils.handleFetchError(err, 'authRecoverAccount');
    });
  },

  handleRecovery(resp, customKeys) {
    return new Promise((resolve, reject) => {
      const {
        result,
        blob_id,
        blob,
        quota,
        patches,
        locked,
        encrypted_blobdecrypt_key,
        encrypted_secretdecrypt_key,
        username,
        ...respRest,
      } = resp;

      const params = {
        url     : customKeys.authInfo.blobvault,
        blob_id : blob_id,
        key     : customKeys.crypt,
      };

      const blobObj = new BlobObj(params);

      Object.assign(blobObj, respRest);

      if (!blobObj.decrypt(blob)) {
        reject(new Error('Error while decrypting blob'));
        return;
      }

      // Apply patches
      if (patches && patches.length) {
        let successful = true;
        patches.forEach((patch) => {
          successful = successful && blobObj.applyEncryptedPatch(patch);
        });

        if (successful) {
          blobObj.consolidate();
        }
      }

      resolve({ blob: blobObj, customKeys });
    });
  },

  /**
   * updateBlob
   * Change the blob data
   * @param {object} opts
   * @param {string} opts.username
   * @param {object} opts.keys
   * @param {object} opts.blob
   * @param {string} masterkey
   */

  updateBlob(opts) {
    const config = {
      method : 'POST',
      url    : `${opts.blob.url}/v1/user/${opts.username}/updateBlob`,
      data   : {
        data     : opts.blob.encrypt(),
        revision : opts.blob.revision,
      },
    };

    const signedRequest = new SignedRequest(config);
    const signed = signedRequest.signAsymmetric(opts.masterkey, opts.blob.data.account_id, opts.blob.id);
    const options = Utils.makeFetchRequestOptions(config);

    return fetch(signed.url, options)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'updateBlob');
    })
  },

  /**
   * updateKeys
   * Change the blob encryption keys
   * @param {object} opts
   * @param {string} opts.username
   * @param {object} opts.keys
   * @param {object} opts.blob
   * @param {string} masterkey
   */

  updateKeys(opts) {
    const old_id  = opts.blob.id;
    opts.blob.id  = opts.keys.id;
    opts.blob.key = opts.keys.crypt;
    opts.blob.encrypted_secret = opts.blob.encryptSecret(opts.keys.unlock, opts.masterkey);

    const recoveryKey = Utils.createRecoveryKey(opts.blob.email);

    const config = {
      method : 'POST',
      url    : `${opts.blob.url}/v1/user/${opts.username}/updatekeys`,
      data   : {
        blob_id  : opts.blob.id,
        data     : opts.blob.encrypt(),
        revision : opts.blob.revision,
        encrypted_secret : opts.blob.encrypted_secret,
        encrypted_blobdecrypt_key : BlobObj.encryptBlobCrypt(recoveryKey, opts.keys.crypt),
        encrypted_secretdecrypt_key : BlobObj.encryptBlobCrypt(recoveryKey, opts.keys.unlock),
      },
    };

    const signedRequest = new SignedRequest(config);
    const signed = signedRequest.signAsymmetric(opts.masterkey, opts.blob.data.account_id, old_id);
    const options = Utils.makeFetchRequestOptions(config);

    return fetch(signed.url, options)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'updateKeys');
    })
  },

  /**
   * Activate an account
   */

  authActivateAccount(opts) {
    const { keys, email, masterkey, address, username, url, authToken, blobData } = opts;

    const params = {
      url,
      blob_id: keys.id,
      key: keys.crypt,
    };

    const blob = new BlobObj(params);

    blob.revision = 0;

    blob.data = {
      ...blobData,
      account_id: address,
      activated: (new Date()).toJSON(),
    };

    blob.encrypted_secret = blob.encryptSecret(keys.unlock, masterkey);

    const recoveryKey = Utils.createRecoveryKey(email);

    const config = {
      method: 'POST',
      url: `${url}/v1/user/${username}/auth/activate`,
      data: {
        address,
        email,
        authToken,
        data: blob.encrypt(),
        encrypted_secret: blob.encrypted_secret,
        encrypted_blobdecrypt_key: BlobObj.encryptBlobCrypt(recoveryKey, keys.crypt),
        encrypted_secretdecrypt_key: BlobObj.encryptBlobCrypt(recoveryKey, keys.unlock),
      },
    };

    const signedRequest = new SignedRequest(config);
    const signed = signedRequest.signAsymmetric(masterkey, address, keys.id);
    const options = Utils.makeFetchRequestOptions(config);

    return fetch(signed.url, options)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve({...data, newBlobData: blob.data, encrypted_secret: blob.encrypted_secret });
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'authActivateAccount');
    })
  },

  authVerifyAccountEmailToken(opts) {
    const { email, emailToken, username, authToken } = opts;
    const config = Utils.makeFetchRequestOptions({
      method : 'POST',
      data: {
        email,
        emailToken,
        authToken,
      }
    });
    const url = `${opts.url}/v1/user/${username}/auth/verify`;
    return fetch(url, config)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    }) 
    .catch((err) => {
      return Utils.handleFetchError(err, 'authVerifyAccountEmailToken');
    });
  },

  authRequestUpdateEmail(opts) {
    const config = {
      method: 'POST',
      url: `${opts.url}/v1/user/${opts.username}/updateEmailRequest`,
      data: opts.data,
    };

    const signedRequest = new SignedRequest(config);
    const signed = signedRequest.signAsymmetric(opts.masterkey, opts.blob.data.account_id, opts.blob.id);
    const options = Utils.makeFetchRequestOptions(config);

    return fetch(signed.url, options)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    }) 
    .catch((err) => {
      return Utils.handleFetchError(err, 'authRequestUpdateEmail');
    });
  },

  authVerifyUpdateEmail(opts) {
    const config = {
      method: 'POST',
      url: `${opts.url}/v1/user/${opts.username}/updateEmailVerify`,
      data: opts.data,
    };

    const signedRequest = new SignedRequest(config);
    const signed = signedRequest.signAsymmetric(opts.masterkey, opts.blob.data.account_id, opts.blob.id);
    const options = Utils.makeFetchRequestOptions(config);

    return fetch(signed.url, options)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    }) 
    .catch((err) => {
      return Utils.handleFetchError(err, 'authVerifyUpdateEmail');
    });
  },

  authRequestUpdatePhone(opts) {
    const config   = {
      method : 'POST',
      url    : `${opts.url}/v1/user/${opts.username}/updatePhoneRequest`,
      data   : opts.data,
    };

    const signedRequest = new SignedRequest(config);
    const signed = signedRequest.signAsymmetric(opts.masterkey, opts.blob.data.account_id, opts.blob.id);
    const options = Utils.makeFetchRequestOptions(config);

    return fetch(signed.url, options)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'authRequestUpdatePhone');
    })
  },

  authVerifyUpdatePhone(opts) {
    const config   = {
      method : 'POST',
      url    : `${opts.url}/v1/user/${opts.username}/updatePhoneVerify`,
      data   : opts.data,
    };

    const signedRequest = new SignedRequest(config);
    const signed = signedRequest.signAsymmetric(opts.masterkey, opts.blob.data.account_id, opts.blob.id);
    const options = Utils.makeFetchRequestOptions(config);

    return fetch(signed.url, options)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'authVerifyUpdatePhone');
    })
  },

  /**
   * Create a blob object
   *
   * @param {object} opts
   * @param {string} opts.url
   * @param {string} opts.id
   * @param {string} opts.crypt
   * @param {string} opts.unlock
   * @param {string} opts.username
   * @param {string} opts.masterkey
   * @param {object} opts.domain
   */
  authCreate(opts) {
    const params = {
      url     : opts.url,
      blob_id : opts.id,
      key     : opts.crypt,
    };
    const blob = new BlobObj(params);

    blob.revision = 0;

    blob.data = {
      auth_secret : crypt.createSecret(8),
      created     : (new Date()).toJSON(),
      phone       : null,
    };

    const recoveryKey = Utils.createRecoveryKey(opts.email);

    // post to the blob vault to create
    const config = Utils.makeFetchRequestOptions({
      method : 'POST',
      data   : {
        blob_id     : opts.id,
        username    : opts.username,
        auth_secret : blob.data.auth_secret,
        data        : blob.encrypt(),
        email       : opts.email,
        hostlink    : opts.activateLink,
        domain      : opts.domain,
        encrypted_blobdecrypt_key : BlobObj.encryptBlobCrypt(recoveryKey, opts.crypt),
        encrypted_secretdecrypt_key : BlobObj.encryptBlobCrypt(recoveryKey, opts.unlock),
      },
    });
    return fetch(`${opts.url}/v1/user/auth`, config)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      blob.identity_id = data.identity_id;
      return Promise.resolve(blob);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'authCreate');
    })
  },

  /**
   * deleteBlob
   * @param {object} options
   * @param {string} options.url
   * @param {string} options.username
   * @param {string} options.blob_id
   * @param {string} options.account_id
   * @param {string} options.masterkey
   */

  deleteBlob(options) {
      const config = {
        method: 'DELETE',
        url: `${options.url}/v1/user/${options.username}`,
      };

      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signAsymmetric(options.masterkey, options.account_id, options.blob_id);
      
      return fetch(signed.url, { method: 'DELETE' })
      .then((resp) => {
        return Utils.handleFetchResponse(resp);
      })
      .then((data) => {
        return Promise.resolve(data);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'deleteBlob');
      })
  },

  /**
   * Block an account
   * @param {object} opts
   * @param {string} opts.url
   * @param {string} opts.username
   * @param {string} opts.masterkey
   * @param {string} opts.account_id
   * @param {string} opts.blob_id
   */

  blockAccount(opts) {
    const config = {
      method : 'POST',
      url    : `${opts.url}/v1/user/${opts.username}/block`,
    };

    const signedRequest = new SignedRequest(config);
    const signed = signedRequest.signAsymmetric(opts.masterkey, opts.account_id, opts.blob_id);

    return fetch(signed.url, { method: 'POST' })
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'blockAccount');
    })
  },

  /**
   * Add bank account
   * @param {object} opts
   * @param {object} opts.blob
   * @param {object} opts.bankAccountInfo
   * @param {string} opts.masterkey
   */

  addBankAccount(opts) {
    const config = {
      method: 'POST',
      url: `${opts.blob.url}/v1/blob/${opts.blob.id}/bankaccount`,
      data: {
        data     : opts.blob.encrypt(),
        revision : opts.blob.revision,
        bank_account_info: opts.bankAccountInfo,
      },
    };

    const signedRequest = new SignedRequest(config);
    const signed = signedRequest.signAsymmetric(opts.masterkey, opts.blob.data.account_id, opts.blob.id);
    const options = Utils.makeFetchRequestOptions(config);

    return fetch(signed.url, options)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'addBankAccount');
    })
  },

  /**
   * Delete bank account
   * @param {object} opts
   * @param {object} opts.blob
   * @param {object} opts.bankAccountInfo
   * @param {string} opts.masterkey
   */

  deleteBankAccount(opts) {
    const config = {
      method: 'DELETE',
      url: `${opts.blob.url}/v1/blob/${opts.blob.id}/bankaccount`,
      data: {
        data     : opts.blob.encrypt(),
        revision : opts.blob.revision,
        bank_account_info: opts.bankAccountInfo,
      },
    };

    const signedRequest = new SignedRequest(config);
    const signed = signedRequest.signAsymmetric(opts.masterkey, opts.blob.data.account_id, opts.blob.id);
    const options = Utils.makeFetchRequestOptions(config);

    return fetch(signed.url, options)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'deleteBankAccount');
    })
  },


  /**
   * get2FA - HMAC signed request
   */

  get2FA(blob) {
    const config = {
      method : 'GET',
      url    : `${blob.url}/v1/blob/${blob.id}/2fa`,
    };
    if (blob.device_id) {
      config.url += `?device_id=${blob.device_id}`;
    }

    const signedRequest = new SignedRequest(config);
    const signed = signedRequest.signHmac(blob.data.auth_secret, blob.id);
    return fetch(signed.url, { method: 'GET' })
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    }) 
    .catch((err) => {
      return Utils.handleFetchError(err, 'get2FA');
    });
  },

  /**
   * set2FA
   * modify 2 factor auth settings
   * @params {object}  opts
   * @params {string}  opts.masterkey
   * @params {boolean} opts.enabled
   * @params {string}  opts.phoneNumber
   * @params {string}  opts.countryCode
   */

  set2FA(opts) {
    const config = {
      method : 'POST',
      url    : `${opts.blob.url}/v1/blob/${opts.blob.id}/2fa`,
      data   : {
        enabled     : opts.enabled,
        phoneNumber : opts.phoneNumber,
        countryCode : opts.countryCode,
      },
    };

    const signedRequest = new SignedRequest(config);
    const signed = signedRequest.signAsymmetric(opts.masterkey, opts.blob.data.account_id, opts.blob.id);
    const options = Utils.makeFetchRequestOptions(config);

    return fetch(signed.url, options)
    .then((resp) => {
      return Utils.handleFetchResponse(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'set2FA');
    })
  }  
};
