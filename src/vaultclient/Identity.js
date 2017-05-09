import crypt from './crypt';

// Identity fields
const identityRoot   = 'identityVault';
const identityFields = [
  'name',
  'entityType',
  'email',
  'phone',
  'address',
  'nationalID',
  'birthday',
  'birthplace',
];

const entityTypes = [
  'individual',
  'organization',
  'corporation',
];

const addressFields = [
  'contact',
  'line1',
  'line2',
  'city',
  'region',  // state/province/region
  'postalCode',
  'country',
];

const nationalIDFields = [
  'number',
  'type',
  'country',
];

const idTypeFields = [
  'ssn',
  'taxID',
  'passport',
  'driversLicense',
  'other',
];

/** *** identity ****/

/**
 * Identity class
 *
 */
export default class Identity {
  constructor(blob) {
    // FIXME why don't declare a member variable for blob directly ?
    this._getBlob = () => {
      return blob;
    };
  }

  /**
   * getFullAddress
   * returns the address formed into a text string
   * @param {string} key - Encryption key
   */

  getFullAddress(key) {
    const blob = this._getBlob();
    if (!blob ||
        !blob.data ||
        !blob.data[identityRoot] ||
        !blob.data[identityRoot].address) {
      return '';
    }

    const address = this.get('address', key);
    let text    = '';

    if (address.value.contact)    text += address.value.contact;
    if (address.value.line1)      text += ' ' + address.value.line1;
    if (address.value.line2)      text += ' ' + address.value.line2;
    if (address.value.city)       text += ' ' + address.value.city;
    if (address.value.region)     text += ' ' + address.value.region;
    if (address.value.postalCode) text += ' ' + address.value.postalCode;
    if (address.value.country)    text += ' ' + address.value.country;
    return text;
  }

  /**
   * getAll
   * get and decrypt all identity fields
   * @param {string} key  - Encryption key
   * @param {function} fn - Callback function
   */

  getAll(key) {
    const blob = this._getBlob();
    if (!blob || !blob.data || !blob.data[identityRoot]) {
      return {};
    }

    const result = {};
    const identity = blob.data[identityRoot];
    for (var i in identity) {
      result[i] = this.get(i, key);
    }

    return result;
  }

  /**
   * get
   * get and decrypt a single identity field
   * @param {string} pointer - Field to retrieve
   * @param {string} key     - Encryption key
   */

  get(pointer, key) {
    const blob = this._getBlob();
    if (!blob || !blob.data || !blob.data[identityRoot]) {
      return null;
    }

    function decrypt(key, data) {
      let value;
      const result = { encrypted: true };

      try {
        value = crypt.decrypt(key, data.value);
      } catch (e) {
        result.value  = data.value;
        result.error  = e;
        return result;
      }

      try {
        result.value = JSON.parse(value);
      } catch (e) {
        result.value = value;
      }

      return result;
    }

    const data = blob.data[identityRoot][pointer];
    if (data && data.encrypted) {
      return decrypt(key, data);
    } else if (data) {
      return data;
    } else {
      return null;
    }
  }

  /**
   * set
   * set and encrypt a single identity field.
   * @param {string} pointer - Field to set
   * @param {string} key     - Encryption key
   * @param {string} value   - Unencrypted data
   * @param {function} fn    - Callback function
   */

  set(pointer, key, value) {
    const self = this;
    const blob = this._getBlob();

    // check fields for validity
    if (identityFields.indexOf(pointer) === -1) {
      return Promise.reject(new Error('invalid identity field'));

    // validate address fields
    } else if (pointer === 'address') {
      if (typeof value !== 'object') {
        return Promise.reject(new Error('address must be an object'));
      }

      for (const addressField in value) {
        if (addressFields.indexOf(addressField) === -1) {
          return Promise.reject(new Error('invalid address field'));
        }
      }

    // validate nationalID fields
    } else if (pointer === 'nationalID') {
      if (typeof value !== 'object') {
        return Promise.reject(new Error('nationalID must be an object'));
      }

      for (const idField in value) {
        if (nationalIDFields.indexOf(idField) === -1) {
          return Promise.reject(new Error('invalid nationalID field'));
        }

        if (idField === 'type') {
          if (idTypeFields.indexOf(value[idField]) === -1) {
            return Promise.reject(new Error('invalid nationalID type'));
          }
        }
      }

    // validate entity type
    } else if (pointer === 'entityType') {
      if (entityTypes.indexOf(value) === -1) {
        return Promise.reject(new Error('invalid entity type'));
      }
    }

    // make sure the identity setup is valid
    function validate() {
      if (!blob) {
        return Promise.reject(new Error('Identity must be associated with a blob'));
      } else if (!blob.data) {
        return Promise.reject(new Error('Invalid Blob'));
      } else if (!blob.data[identityRoot]) {
        return blob.set(`/${identityRoot}`, {})
          .then((res) => {
            return Promise.resolve();
          });
      } else {
        return Promise.resolve();
      }
    }

    function encrypt(key, value) {
      if (typeof value === 'object') value = JSON.stringify(value);
      return crypt.encrypt(key, value);
    }

    function set() {
      // NOTE: currently we will overwrite if it already exists
      // the other option would be to require decrypting with the
      // existing key as a form of authorization
      // var current = self.get(pointer, key);
      // if (current && current.error) {
      //  return fn ? fn(current.error) : undefined;
      // }

      const data = {};
      data[pointer] = {
        encrypted : !!key,
        value     : key ? encrypt(key, value) : value,
      };

      return self._getBlob().extend(`/${identityRoot}`, data);
    }

    return validate()
      .then(() => {
        return set();
      });
  }

  /**
   * unset
   * remove a single identity field - will only be removed
   * with a valid decryption key
   * @param {string} pointer - Field to remove
   * @param {string} key     - Encryption key
   * @param {function} fn    - Callback function
   */

  unset(pointer, key) {
    // NOTE: this is rather useless since you can overwrite
    // without an encryption key
    const data = this.get(pointer, key);
    if (data && data.error) {
      return Promise.reject(data.error);
    }

    return this._getBlob().unset(`/${identityRoot}/${pointer}`);
  }
}

export { identityRoot };
