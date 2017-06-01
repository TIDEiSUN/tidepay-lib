import Utils from '../common/utils';

export default {
  getAuthInfo(domain, queryString) {
    return fetch(`${domain}/tidepayurl`)
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .then((value) => {
        if (!value.authinfo) {
          return Promise.reject(new Error(`Authentication is not supported on ${domain}`));
        }

        let url = value.authinfo;
        let qs = '?';
        Object.keys(queryString).forEach((key) => {
          if (qs !== '?') {
            qs += '&';
          }
          qs += `${key}=${queryString[key]}`;
        });
        if (qs !== '?') {
          url += qs;
        }
        return fetch(url);
      })
      .then((resp) => {
        return Utils.handleFetchResponse(resp);
      });
  }
};
