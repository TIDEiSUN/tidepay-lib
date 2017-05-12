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

class VaultClientClass {
  constructor(isunpayrpcURL) {
    // initialize vault client
    this.client = new BlobVaultAPI(isunpayrpcURL);
  }

  unlockAccount(loginInfo) {
    if (loginInfo.secret) {
      return Promise.resolve(loginInfo);
    }
    console.log('unlock: new login info');
    const newLoginInfo = this.deserializeLoginInfo(this.serializeLoginInfo(loginInfo));
    return this.client.unlock(newLoginInfo.blob.encrypted_secret, newLoginInfo.customKeys)
      .then((result) => {
        newLoginInfo.secret = result.secret;
        return Promise.resolve(newLoginInfo);
      });
  }

  updateBlob(username, loginInfo) {
    return this.unlockAccount(loginInfo)
      .then((unlockedLoginInfo) => {
        if (unlockedLoginInfo === loginInfo) {
            console.log('change password: new login info');
        }
        const newLoginInfo = unlockedLoginInfo === loginInfo ? this.deserializeLoginInfo(this.serializeLoginInfo(loginInfo)) : unlockedLoginInfo;
        const options = {
          username: username,
          masterkey: newLoginInfo.secret,
          blob: newLoginInfo.blob,
          customKeys: newLoginInfo.customKeys,
        };
        return this.client.updateBlob(options)
          .then((resolved) => {
            return Promise.resolve({ ...resolved, loginInfo: newLoginInfo });
          });
      });
  }

  changePassword(username, newPassword, loginInfo) {
    return this.unlockAccount(loginInfo)
      .then((unlockedLoginInfo) => {
        if (unlockedLoginInfo === loginInfo) {
            console.log('change password: new login info');
        }
        const newLoginInfo = unlockedLoginInfo === loginInfo ? this.deserializeLoginInfo(this.serializeLoginInfo(loginInfo)) : unlockedLoginInfo;
        const options = {
          username: username,
          password: newPassword,
          masterkey: newLoginInfo.secret,
          blob: newLoginInfo.blob,
          customKeys: newLoginInfo.customKeys,
        };
        return this.client.changePassword(options)
          .then((resolved) => {
            if (Object.prototype.hasOwnProperty.call(resolved, 'last_id_change_date')) {
              newLoginInfo.blob.last_id_change_date = resolved.last_id_change_date;
              newLoginInfo.blob.last_id_change_timestamp = resolved.last_id_change_timestamp;
            }
            return Promise.resolve({ ...resolved, loginInfo: newLoginInfo });
          });
      });
  }

  authActivateAccount(loginInfo, email, authToken, createAccountToken) {
    const { customKeys, blob } = loginInfo;
    const { data } = blob;
    return this.client.authActivateAccount(customKeys, email, authToken, data, createAccountToken)
      .then((resp) => {
        const { result, loginToken, newBlobData, secret } = resp;
        const resultLoginInfo = updateLoginInfo(loginInfo, result, newBlobData);
        resultLoginInfo.secret = secret;
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
      .then((unlockedLoginInfo) => {
        const options = {
          masterkey: unlockedLoginInfo.secret,
          enabled: enable,
          phoneNumber: phone.phoneNumber,
          countryCode: phone.countryCode,
          blob: unlockedLoginInfo.blob,
        };
        return BlobAPI.set2FA(options)
          .then((result) => {
            return Promise.resolve({ ...result, loginInfo: unlockedLoginInfo });
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

  createCustomKeys(username, password) {
    return this.client.getAuthInfo(username)
    .then((authInfo) => {
      if (!authInfo.exists) {
        return Promise.reject(new Error('User does not exists.'));
      }
      const customKeys = new CustomKeys(authInfo, password);
      return Promise.resolve(customKeys);
    });
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
      .then((unlockedLoginInfo) => {
        const options = {
          url: unlockedLoginInfo.blob.url,
          blob: unlockedLoginInfo.blob,
          masterkey: unlockedLoginInfo.secret,
          username: unlockedLoginInfo.username,
          data: {
            email,
            hostlink,
          },
        };
        return this.client.authRequestUpdateEmail(options)
          .then((resp) => {
            const { result, ...restResp } = resp;
            const resultLoginInfo = updateLoginInfo(unlockedLoginInfo, result);
            return Promise.resolve({ ...restResp, loginInfo: resultLoginInfo });
          });
      });
  }

  authVerifyUpdateEmail(loginInfo, email, emailToken, authToken) {
    return this.unlockAccount(loginInfo)
      .then((unlockedLoginInfo) => {
        const { customKeys } = unlockedLoginInfo;
        const recoveryKey = Utils.createRecoveryKey(email);
        const data = {
          email,
          emailToken,
          authToken,
          encrypted_blobdecrypt_key: BlobObj.encryptBlobCrypt(recoveryKey, customKeys.crypt),
          encrypted_secretdecrypt_key: BlobObj.encryptBlobCrypt(recoveryKey, customKeys.unlock),
        };

        const options = {
          url: unlockedLoginInfo.blob.url,
          blob: unlockedLoginInfo.blob,
          masterkey: unlockedLoginInfo.secret,
          username: unlockedLoginInfo.username,
          data,
        };
        return this.client.authVerifyUpdateEmail(options)
          .then((resp) => {
            const { result, ...restResp } = resp;
            const resultLoginInfo = updateLoginInfo(unlockedLoginInfo, result);
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

  authRequestUpdatePhone(loginInfo, phone) {
    return this.unlockAccount(loginInfo)
      .then((unlockedLoginInfo) => {
        const { countryCode, phoneNumber } = phone;

        const options = {
          url: unlockedLoginInfo.blob.url,
          blob: unlockedLoginInfo.blob,
          masterkey: unlockedLoginInfo.secret,
          username: unlockedLoginInfo.username,
          data: {
            countryCode,
            phoneNumber,
            via: 'sms',
          },
        };

        return this.client.authRequestUpdatePhone(options)
          .then((resp) => {
            const { result, ...restResp } = resp;
            const resultLoginInfo = updateLoginInfo(unlockedLoginInfo, result);
            return Promise.resolve({ ...restResp, loginInfo: resultLoginInfo });
          });
      });
  }

  authVerifyUpdatePhone(loginInfo, phone, phoneToken, authToken, newBlob) {
    return this.unlockAccount(loginInfo)
      .then((unlockedLoginInfo) => {
        const { blob, secret, username } = unlockedLoginInfo;
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

        return this.client.authVerifyUpdatePhone(options)
          .then((resp) => {
            const { result, ...restResp } = resp;
            const resultLoginInfo = updateLoginInfo(unlockedLoginInfo, result, newBlob.data);
            return Promise.resolve({ ...restResp, loginInfo: resultLoginInfo });
          });
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
        const { blob, secret, customKeys } = results;

        return Promise.resolve({
          blob,
          customKeys,
          secret,
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
    return JSON.stringify(loginInfo);
  }

  deserializeLoginInfo(str) {
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

  blockAccount(username, loginInfo) {
    return this.unlockAccount(loginInfo)
      .then((unlockedLoginInfo) => {
        const options = {
          url: unlockedLoginInfo.blob.url,
          blob_id: unlockedLoginInfo.blob.id,
          username: username,
          account_id: unlockedLoginInfo.blob.data.account_id,
          masterkey: unlockedLoginInfo.secret,
        };
        return this.client.blockAccount(options)
          .then((result) => {
            return Promise.resolve({ ...result, loginInfo: unlockedLoginInfo });
          });
      });    
  }
  uploadPhotos(loginInfo, formData, config){
    const newLoginInfo = this.deserializeLoginInfo(this.serializeLoginInfo(loginInfo));
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
      .then((unlockedLoginInfo) => {
        if (unlockedLoginInfo === loginInfo) {
          console.log('add bank account: new login info');
        }

        const newLoginInfo = unlockedLoginInfo === loginInfo ? this.deserializeLoginInfo(this.serializeLoginInfo(loginInfo)) : unlockedLoginInfo;
        updateBlobDataCallback(newLoginInfo.blob.data);

        const options = {
          masterkey: newLoginInfo.secret,
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
      .then((unlockedLoginInfo) => {
        if (unlockedLoginInfo === loginInfo) {
          console.log('delete bank account: new login info');
        }

        const newLoginInfo = unlockedLoginInfo === loginInfo ? this.deserializeLoginInfo(this.serializeLoginInfo(loginInfo)) : unlockedLoginInfo;
        updateBlobDataCallback(newLoginInfo.blob.data);

        const options = {
          masterkey: newLoginInfo.secret,
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
