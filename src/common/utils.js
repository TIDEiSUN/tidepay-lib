import parser from 'url';
import Errors from './Errors';

export default {
  makeFetchRequestOptions(config) {
    const options = {
      method: config.method,
      headers: {},
    };
    if (config.data) {
      if (config.data instanceof FormData) {
        options.body = config.data;
      } else {
        options.body = JSON.stringify(config.data);
        options.headers['Content-Type'] = 'application/json';
      }
    }
    if (config.authorization) {
      options.headers.Authorization = `Bearer ${config.authorization}`;
    }
    return options;
  },

  handleFetchResponse(resp) {
    if (resp.status < 200 || resp.status > 299) {
      const contentType = resp.headers.get('content-type');
      if (contentType && contentType.indexOf('application/json') !== -1) {
        setTimeout(() => null, 0);
        return resp.json().then((err) => {
          const { code, message, ...info } = err;
          return Promise.reject(new Errors.FetchError(resp.status, message, code, info));
        });
      }
      return Promise.reject(new Errors.FetchError(resp.status, resp.statusText));
    }
    setTimeout(() => null, 0);
    return resp.json();
  },

  handleFetchResponseAndHeaders(resp) {
    return this.handleFetchResponse(resp)
      .then((json) => {
        return { data: json, headers: resp.headers };
      });
  },

  addQueryString(baseUrl, queryString) {
    const qsArray = [];
    Object.keys(queryString).forEach((key) => {
      const value = queryString[key];
      if (value !== null && value !== undefined) {
        if (Array.isArray(value)) {
          const mappedArray = value.map(arrayValue => `${key}=${arrayValue}`);
          qsArray.push(...mappedArray);
        } else {
          qsArray.push(`${key}=${value}`);
        }
      }
    });

    if (qsArray.length > 0) {
      const parsed = parser.parse(baseUrl);
      return baseUrl.concat(parsed.search ? '&' : '?', qsArray.join('&'));
    }
    return baseUrl;
  },

  handleFetchError(err, message) {
    // console.error(`${message}:`, err);
    return Promise.reject(err);
  },
};
