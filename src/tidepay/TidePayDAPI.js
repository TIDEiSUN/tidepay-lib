import fetch from 'isomorphic-fetch';
import Utils from '../common/utils';

export default class TidePayAPIDClass {
  constructor(url) {
    this.tidepaydURL = `${url}/`;
  }

  static buildOptions(method, params) {
    return {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(
        {
          method,
          params: [
            params,
          ],
        },
      ),
    };
  }
  accountLines(params) {
    const options = TidePayAPIDClass.buildOptions('account_lines', params);
    return fetch(this.tidepaydURL, options)
      .then(resp => Utils.handleFetchResponse(resp));
  }
  norippleCheck(params) {
    const options = TidePayAPIDClass.buildOptions('noripple_check', params);
    return fetch(this.tidepaydURL, options)
      .then(resp => Utils.handleFetchResponse(resp));
  }
  random() {
    const options = TidePayAPIDClass.buildOptions('random', {});
    return fetch(this.tidepaydURL, options)
      .then(resp => Utils.handleFetchResponse(resp));
  }
}
