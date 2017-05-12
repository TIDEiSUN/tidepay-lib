import ExtendableError from 'es6-error';

class FetchError extends ExtendableError {
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
