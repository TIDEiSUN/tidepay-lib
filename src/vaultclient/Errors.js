// FIXME instanceof Errors.FetchError does not work

class BaseError extends Error {
  constructor(message) {
    super(message);
    this.name = this.constructor.name;
    if (typeof Error.captureStackTrace === 'function') {
      Error.captureStackTrace(this, this.constructor);
    } else {
      this.stack = (new Error(message)).stack;
    }
  }
}

class FetchError extends BaseError {
  constructor(status, text, code = null, info = null) {
    let message;
    if (code !== null) {
      message = `HTTP status: ${status} (${code} - ${text})`;
    } else {
      message = `HTTP status: ${status} (${text})`;
    }
    super(message);
    this.code = code;
    if (info && Object.keys(info).length > 0) {
      this.info = info;
    } else {
      this.info = null;
    }
  }
}

export default {
  FetchError,
};
