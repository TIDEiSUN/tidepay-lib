import { post } from 'axios';
import BlobVaultAPI from './BlobVaultAPI';
import Errors from './Errors'
import Utils from './utils';
import BlobAPI from './blob';
import BlobObj from './BlobObj';
import CustomKeys from './customkeys';

function updateLoginInfo(loginInfo, result, newBlobData = null) {
  if (!loginInfo) {
    // not logged in, do not update
    return loginInfo;
  }
  let newBlob = loginInfo.blob;
  if (newBlobData) {
    newBlob = { ...newBlob, data: newBlobData };
  }
  let newAuthInfo = loginInfo.customKeys.authInfo;

  if (result) {
    const { updateFields, deleteFields } = result;
    const hasUpdate = updateFields && Object.keys(updateFields).length > 0;
    const hasDelete = deleteFields && Object.keys(deleteFields).length > 0;
    if (hasDelete) {
      const { blob, authInfo } = deleteFields;
      if (blob) {
        newBlob = { ...newBlob };
        Object.keys(blob).forEach((key) => {
          delete newBlob[key];
        });
      }
      if (authInfo) {
        newAuthInfo = { ...newAuthInfo };
        Object.keys(authInfo).forEach((key) => {
          delete newAuthInfo[key];
        });
      }
    }
    if (hasUpdate) {
      const { blob, authInfo } = updateFields;
      if (blob) {
        newBlob = { ...newBlob, ...blob };
      }
      if (authInfo) {
        newAuthInfo = { ...newAuthInfo, ...authInfo };
      }
    }
  }
  let newCustomKeys = loginInfo.customKeys;
  if (newAuthInfo !== loginInfo.customKeys.authInfo) {
    newCustomKeys = CustomKeys.deserialize(loginInfo.customKeys);
    newCustomKeys.authInfo = newAuthInfo;
  }
  return { ...loginInfo, blob: newBlob, customKeys: newCustomKeys };
}

function checkEmailVerified(authInfo) {
  if (!authInfo.exists) {
    return Promise.reject(new Error('User does not exists.'));
  }
  if (!authInfo.emailVerified) {
    return Promise.reject(new Error('Account has not been verified.'));
  }
  return Promise.resolve();
}

function serializeLoginInfo(loginInfo) {
  return JSON.stringify(loginInfo);
}

function deserializeLoginInfo(str) {
  const strData = JSON.parse(str);
  if (!Object.prototype.hasOwnProperty.call(strData, 'blob')) {
    return strData;
  }

  const {
    blob,
    customKeys,
    ...strDataRest
  } = strData;

  const blobObj = BlobObj.deserialize(blob);
  const customKeysObj = CustomKeys.deserialize(customKeys);

  return { blob: blobObj, customKeys: customKeysObj, ...strDataRest };
}

function cloneLoginInfo(loginInfo) {
  return deserializeLoginInfo(serializeLoginInfo(loginInfo));
}

class VaultClientClass {
  constructor(isunpayrpcURL) {
    // initialize vault client
    this.client = new BlobVaultAPI(isunpayrpcURL);
  }

  unlockAccount(loginInfo) {
    const { customKeys, blob } = loginInfo;
    const { encrypted_secret } = blob;
    return this.client.unlock(encrypted_secret, customKeys);
  }

  updateBlob(username, loginInfo, newBlob) {
    const _updateBlob = (secret, customKeys) => {
      const options = {
        username,
        masterkey: secret,
        blob: newBlob,
      };

      // TODO blob.key
      const { authInfo } = customKeys;
      return checkEmailVerified(authInfo)
        .then(() => this.client.updateBlob(options));
    };

    return this.unlockAccount(loginInfo)
      .then(secret => _updateBlob(secret, loginInfo.customKeys))
      .then((resolved) => {
        const newLoginInfo = cloneLoginInfo(loginInfo);
        newLoginInfo.blob = newBlob;
        return Promise.resolve({ ...resolved, loginInfo: newLoginInfo });
      });
  }

  changePassword(username, newPassword, loginInfo) {
    const _changePassword = (blob, secret, oldCustomKeys, newCustomKeys) => {
      const options = {
        username,
        masterkey: secret,
        blob,
        keys: newCustomKeys,
      };

      // TODO update blob.key

      const { authInfo } = oldCustomKeys;
      return checkEmailVerified(authInfo)
        .then(() => this.client.changePassword(options))
        .then(resolved => Promise.resolve({ newCustomKeys, resolved }));
    };

    const newCustomKeysPromise = this.createAndDeriveCustomKeys(username, newPassword, loginInfo.customKeys.authInfo);
    const unlockPromise = this.unlockAccount(loginInfo);
    return Promise.all([
      unlockPromise,
      newCustomKeysPromise,
    ])
      .then(([secret, newCustomKeys]) => _changePassword(loginInfo.blob, secret, loginInfo.customKeys, newCustomKeys))
      .then((results) => {
        const { newCustomKeys, resolved } = results;
        const newLoginInfo = cloneLoginInfo(loginInfo);
        if (Object.prototype.hasOwnProperty.call(resolved, 'last_id_change_date')) {
          newLoginInfo.blob.last_id_change_date = resolved.last_id_change_date;
          newLoginInfo.blob.last_id_change_timestamp = resolved.last_id_change_timestamp;
        }
        newLoginInfo.customKeys = newCustomKeys;
        return Promise.resolve({ ...resolved, loginInfo: newLoginInfo });
      });
  }

  authActivateAccount(loginInfo, email, authToken, createAccountToken) {
    const { customKeys, blob } = loginInfo;
    const { data } = blob;
    return this.client.authActivateAccount(customKeys, email, authToken, data, createAccountToken)
      .then((resp) => {
        const { result, loginToken, newBlobData, encrypted_secret } = resp;
        const resultLoginInfo = updateLoginInfo(loginInfo, result, newBlobData);
        resultLoginInfo.blob.encrypted_secret = encrypted_secret;
        return Promise.resolve({ loginInfo: resultLoginInfo, loginToken });
      });
  }

  authVerifyAccountEmailToken(username, email, emailToken, authToken) {
    return this.client.authVerifyAccountEmailToken(username, email, emailToken, authToken);
  }

  authRegisterAccount(username, password, email, activateLink, domain) {
    const options = {
      username: username,
      password: password,
      email: email,
      activateLink: activateLink,
      domain: domain,
    };
    return this.client.authRegister(options);
  }

  get2FAInfo(loginInfo) {
    return BlobAPI.get2FA(loginInfo.blob);
  }

  set2FAInfo(loginInfo, enable, phone) {
    return this.unlockAccount(loginInfo)
      .then((secret) => {
        const { blob } = loginInfo;
        const options = {
          masterkey: secret,
          enabled: enable,
          phoneNumber: phone.phoneNumber,
          countryCode: phone.countryCode,
          blob,
        };
        return BlobAPI.set2FA(options)
          .then((result) => {
            return Promise.resolve({ ...result, loginInfo });
          });
      });
  }

  authLoginAccount(authInfo, data) {
    const options = {
      url: authInfo.blobvault,
      data,
    };
    console.log('authlogin info', options)
    return this.client.authLogin(options);
  }

  createAndDeriveCustomKeys(username, password, inAuthInfo = null) {
    const authInfoPromise = inAuthInfo ? Promise.resolve(inAuthInfo) : this.client.getAuthInfo(username);
    
    return authInfoPromise
    .then((authInfo) => {
      
      
      if (!authInfo.exists) {
        return Promise.reject(new Error('User does not exists.'));
      }
      const customKeys = new CustomKeys(authInfo, password);
      
      return customKeys.deriveKeys(password).then((result)=>{
        
        
        return Promise.resolve(result);

      })
     
      
    })
  }

  handleLogin(resp, customKeys) {
    const options = {
      url: customKeys.authInfo.blobvault,
      blob_id: customKeys.id,
      key: customKeys.crypt,
    };
    const blobObj = new BlobObj(options);
    return blobObj.init(resp)
      .then((blob) => {
        // TODO still needed?
        // save for relogin
        const { authInfo } = customKeys;
        this.client.infos[customKeys.id] = authInfo;
        return Promise.resolve({
          blob,
          customKeys,
          username: authInfo.username,
        });
      });
  }

  authUnblockAccount(data) {
    const dummyUsername = 'dummy';
    return this.client.getByUsername(dummyUsername)
      .then((authInfo) => {
        const options = {
          url: authInfo.blobvault,
          data,
        };
        return this.client.authUnblockAccount(options);
      });
  }

  authRecoverAccount(data) {
    const dummyUsername = 'dummy';
    return this.client.getByUsername(dummyUsername)
      .then((authInfo) => {
        const options = {
          url: authInfo.blobvault,
          data,
        };
        return this.client.authRecoverAccount(options);
      });
  }

  authRequestUpdateEmail(loginInfo, email, hostlink) {
    return this.unlockAccount(loginInfo)
      .then((secret) => {
        const { blob, username } = loginInfo;
        const options = {
          url: blob.url,
          blob,
          masterkey: secret,
          username,
          data: {
            email,
            hostlink,
          },
        };
        return this.client.authRequestUpdateEmail(options)
          .then((resp) => {
            const { result, ...restResp } = resp;
            const resultLoginInfo = updateLoginInfo(loginInfo, result);
            return Promise.resolve({ ...restResp, loginInfo: resultLoginInfo });
          });
      });
  }

  authVerifyUpdateEmail(loginInfo, email, emailToken, authToken) {
    return this.unlockAccount(loginInfo)
      .then((secret) => {
        const { customKeys, blob, username } = loginInfo;
        const recoveryKey = Utils.createRecoveryKey(email);
        const data = {
          email,
          emailToken,
          authToken,
          encrypted_blobdecrypt_key: BlobObj.encryptBlobCrypt(recoveryKey, customKeys.crypt),
          encrypted_secretdecrypt_key: BlobObj.encryptBlobCrypt(recoveryKey, customKeys.unlock),
        };

        const options = {
          url: blob.url,
          blob,
          masterkey: secret,
          username,
          data,
        };
        return this.client.authVerifyUpdateEmail(options)
          .then((resp) => {
            const { result, ...restResp } = resp;
            const resultLoginInfo = updateLoginInfo(loginInfo, result);
            return Promise.resolve({ ...restResp, loginInfo: resultLoginInfo });
          });
      });
  }

  cloneBlob(blob) {
    const { data } = blob;
    // assume no function
    const newData = JSON.parse(JSON.stringify(data));
    return Object.assign(new BlobObj(), blob, { data: newData });
  }

  sumUpdateLoginInfo(loginInfo, result, newBlobData) {
    return updateLoginInfo(loginInfo, result, newBlobData);
  }

  authRequestUpdatePhone(loginInfo, phone) {
    const _authRequestUpdatePhone = (username, blob, secret) => {
      const { countryCode, phoneNumber } = phone;

      const options = {
        url: blob.url,
        blob,
        masterkey: secret,
        username,
        data: {
          countryCode,
          phoneNumber,
          via: 'sms',
        },
      };

      return this.client.authRequestUpdatePhone(options);
    }

    return this.unlockAccount(loginInfo)
      .then(secret => _authRequestUpdatePhone(loginInfo.username, loginInfo.blob, secret))
      .then((resp) => {
        const { result, ...restResp } = resp;
        const resultLoginInfo = updateLoginInfo(loginInfo, result);
        return Promise.resolve({ ...restResp, loginInfo: resultLoginInfo });
      });
  }

  authVerifyUpdatePhone(loginInfo, phone, phoneToken, authToken, newBlob) {
    const _authVerifyUpdatePhone = (blob, secret, username) => {
      const { phoneNumber, countryCode } = phone;
      const data = {
        countryCode,
        phoneNumber,
        phoneToken,
        authToken,
        data: newBlob.encrypt(),
        revision: newBlob.revision,
      };

      const options = {
        url: blob.url,
        blob,
        masterkey: secret,
        username,
        data,
      };

      return this.client.authVerifyUpdatePhone(options);
    }

    return this.unlockAccount(loginInfo)
      .then(secret => _authVerifyUpdatePhone(loginInfo.blob, secret, loginInfo.username))
      .then((resp) => {
        const { result, ...restResp } = resp;
        const resultLoginInfo = updateLoginInfo(loginInfo, result, newBlob.data);
        return Promise.resolve({ ...restResp, loginInfo: resultLoginInfo });
      });
  }

  handleRecovery(resp, email) {
    const { username } = resp;
    return this.client.getByUsername(username)
      .then((authInfo) => {
        const { blob_id, encrypted_blobdecrypt_key, encrypted_secretdecrypt_key } = resp;
        const customKeys = new CustomKeys(authInfo, null);

        customKeys.id = blob_id;
        const recoveryKey = Utils.createRecoveryKey(email);
        try {
          customKeys.crypt = BlobObj.decryptBlobCrypt(recoveryKey, encrypted_blobdecrypt_key);
          customKeys.unlock = BlobObj.decryptBlobCrypt(recoveryKey, encrypted_secretdecrypt_key);
        } catch (err) {
          console.error('Cannot decrypt by recover key', err);
          return Promise.reject(new Error('Incorrect recover key'));
        }
        return this.client.handleRecovery(resp, customKeys);
      })
      .then((results) => {
        const { blob, customKeys } = results;

        return Promise.resolve({
          blob,
          customKeys,
          username: customKeys.authInfo.username,
        });
      });
  }

  getAuthInfoByEmail(email) {
    return this.client.getByEmail(email);
  }
  getAuthInfoByUsername(username){
    return this.client.getByUsername(username);
  }

  serializeLoginInfo(loginInfo) {
    return serializeLoginInfo(loginInfo);
  }

  deserializeLoginInfo(str) {
    return deserializeLoginInfo(str);
  }

  blockAccount(username, loginInfo) {
    return this.unlockAccount(loginInfo)
      .then((secret) => {
        const { blob } = loginInfo;
        const options = {
          url: blob.url,
          blob_id: blob.id,
          username,
          account_id: blob.data.account_id,
          masterkey: secret,
        };
        return this.client.blockAccount(options)
          .then((result) => {
            return Promise.resolve({ ...result, loginInfo: loginInfo });
          });
      });    
  }

  uploadPhotos(loginInfo, formData, config){
    const newLoginInfo = cloneLoginInfo(loginInfo);
    let url = `${loginInfo.blob.url}/v1/blob/${loginInfo.blob.id}/uploadId`;
    return post(url, formData, config)
      .then((resp) => {
        newLoginInfo.blob.id_photos = resp.data.id_photos;
        return Promise.resolve({ loginInfo: newLoginInfo });
      })
      .catch((err) => {
        if (err.response) {
          const body = err.response.data;
          return Promise.reject(new Error(`${body.code} - ${body.message}`));
        } else {
          return Promise.reject(err);
        }
      });
  }

  addBankAccount(loginInfo, bankAccountInfo, updateBlobDataCallback) {
    return this.unlockAccount(loginInfo)
      .then((secret) => {
        const newLoginInfo = cloneLoginInfo(loginInfo);

        updateBlobDataCallback(newLoginInfo.blob.data);

        const options = {
          masterkey: secret,
          blob: newLoginInfo.blob,
          bankAccountInfo,
        };

        return this.client.addBankAccount(options)
          .then((resolved) => {
            return Promise.resolve({ ...resolved, loginInfo: newLoginInfo });
          });
      });
  }

  deleteBankAccount(loginInfo, bankAccountInfo, updateBlobDataCallback) {
    return this.unlockAccount(loginInfo)
      .then((secret) => {
        const newLoginInfo = cloneLoginInfo(loginInfo);
        updateBlobDataCallback(newLoginInfo.blob.data);

        const options = {
          masterkey: secret,
          blob: newLoginInfo.blob,
          bankAccountInfo,
        };
        return this.client.deleteBankAccount(options)
          .then((resolved) => {
            return Promise.resolve({ ...resolved, loginInfo: newLoginInfo });
          });
      });
  }

  getBlob(token) {
    const dummyUsername = 'dummy';
    return this.client.getByUsername(dummyUsername)
      .then((authInfo) => {
        return this.client.getBlob(authInfo.blobvault, token);
      });
  }
}

export default VaultClientClass;
export { Utils, Errors };
