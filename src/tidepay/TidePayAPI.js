import Utils from '../common/utils';
import sign from './transaction/sign';

export default class TidePayAPIClass {
  constructor(isunpayrpcURL) {
    this.isunpayrpcURL = isunpayrpcURL;
    this.dataapiURL = null;
  }

  getDataApiUrl() {
    if (this.dataapiURL) {
      return Promise.resolve(this.dataapiURL);
    }
    return fetch(`${this.isunpayrpcURL}/tidepayurl`)
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .then((value) => {
        this.dataapiURL = value.dataapi;
        console.log('data api url', this.dataapiURL);
        return Promise.resolve(this.dataapiURL);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getDataApiUrl');
      });
  }

  getGatewayAddress() {
    return fetch(`${this.isunpayrpcURL}/gatewayaddress`)
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getGatewayAddress');
      });
  }

  getCurrencies() {
    return fetch(`${this.isunpayrpcURL}/currency`)
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getCurrencies');
      });
  }

  /**
   * Get the latest withdrawal fee
   * @param {String} currency Currency to query (3-letter code)
   */
  getWithdrawalFee(currency = null) {
    const qs = { currency };
    const url = Utils.addQueryString(`${this.isunpayrpcURL}/withdrawalfee`, qs);

    return fetch(url)
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getWithdrawalFee');
      });
  }

  /**
   * Get the latest exchange rate
   * @param {String} base Base currency (3-letter code)
   * @param {String|Array} symbols Limit results to specific currencies (3-letter codes)
   */
  getExchangeRate(base = null, symbols = null) {
    return this.getDataApiUrl()
      .then((dataApiUrl) => {
        const qs = { base, symbols };
        const url = Utils.addQueryString(`${dataApiUrl}/exchange/rates`, qs);

        return fetch(url);
      })
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getExchangeRate');
      });
  }

  previewExchange(fromCurrency, fromValue, toCurrency) {
    const qs = {
      base: fromCurrency,
      symbols: toCurrency,
    };
    const url = Utils.addQueryString(`${this.isunpayrpcURL}/exchangerate`, qs);

    return fetch(url)
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'previewExchange');
      });
  }

  // TODO
  // submigExchangeRequest() {
  // }

  getAccountBalances(address, options = {}) {
    return this.getDataApiUrl()
      .then((data_apiURL) => {
        const qs = {
          currency: options.currency,
        };
        const url = Utils.addQueryString(`${data_apiURL}/accounts/${address}/balances`, qs);

        return fetch(url)
          .then((resp) => {
            return Utils.handleFetchResponse(resp);
          })
          .then((json) => {
            return json.result;
          })
          .catch((err) => {
            return Utils.handleFetchError(err, 'getAccountBalances');
          });
      });
  }

  getTransactionDetail(tx_hash) {
    return this.getDataApiUrl().
      then((data_apiURL) => {
        const url = `${data_apiURL}/transactions/${tx_hash}`

        return fetch(url).
          then((resp) => {
            return Utils.handleFetchResponse(resp);
          })
          .catch((err) => {
            return Utils.handleFetchError(err, 'getTransactionsDetail');
          });
      })
  }

  getAccountTransactions(myAddress, options = {}) {
    return this.getDataApiUrl()
      .then((data_apiURL) => {
        const qs = {
          type: 'Payment',
          descending: true,
          result: 'tesSUCCESS',
          currency: options.currency,
          start: options.start,
          end: options.end,
        };
        const url = Utils.addQueryString(`${data_apiURL}/accounts/${myAddress}/transactions`, qs);

        return fetch(url)
          .then((resp) => {
            return Utils.handleFetchResponse(resp);
          })
          .catch((err) => {
            return Utils.handleFetchError(err, 'getAccountTransactions');
          });
      });
  }



  sendPayment(sourceAccount, payment) {
    const pconfig = {
      method: 'POST',
      data: payment,
    };

    const poptions = Utils.makeFetchRequestOptions(pconfig);
    return fetch(`${this.isunpayrpcURL}/preparePayment`, poptions)
      .then((resp) => {
        return Utils.handleFetchResponse(resp);
      })
      .then((prepared) => {
        const signedData = sign(prepared.txJSON, sourceAccount.secret);

        const config = {
          method: 'POST',
          data: {
            signed: signedData,
            maxLedgerVersion: prepared.instructions.maxLedgerVersion,
          },
        };

        const options = Utils.makeFetchRequestOptions(config);

        return fetch(`${this.isunpayrpcURL}/signedTransaction`, options)
          .then((resp) => {
            return Utils.handleFetchResponse(resp);
          })
          .then((data) => {
            return Promise.resolve(data);
          })
          .catch((err) => {
            return Utils.handleFetchError(err, 'sendPayment');
          });
      });
  }

  sendInternalPayment(gatewayAddress, sourceAccount, destinationAddress, currency, value) {
    const amount = {
      currency,
      value,
      counterparty: gatewayAddress,
    };
    const payment = {
      source: {
        address: sourceAccount.address,
        maxAmount: amount,
      },
      destination: {
        address: destinationAddress,
        amount: amount,
      },
    };
    return this.sendPayment(sourceAccount, payment);
  }

  sendExternalPayment(gatewayAddress, sourceAccount, currency, value, memo = null) {
    const amount = {
      currency,
      value,
      counterparty: gatewayAddress,
    };
    const payment = {
      source: {
        address: sourceAccount.address,
        maxAmount: amount,
      },
      destination: {
        address: gatewayAddress,
        amount: amount,
      },
    };
    if (memo) {
      payment.memos = [{
        data: JSON.stringify(memo),
        format: 'application/JSON',
      }];
    }
    return this.sendPayment(sourceAccount, payment);
  }

  exchangeCurrency(gatewayAddress, account, fromCurrency, fromValue, toCurrency, exchangeRate) {
    const payment = {
      source: {
        address: account.address,
        amount: {
          currency: fromCurrency,
          value: fromValue,
          counterparty: gatewayAddress,
        },
      },
      destination: {
        address: account.address,
        minAmount: {
          currency: toCurrency,
          value: String(fromValue * exchangeRate),
          counterparty: gatewayAddress,
        },
      },
    };
    return this.sendPayment(account, payment);
  }

  getAccountPockets(gatewayAddress, address) {
    return this.getDataApiUrl()
      .then((data_apiURL) => {
        const options = {
          counterparty: gatewayAddress,
        };
        const url = Utils.addQueryString(`${data_apiURL}/accounts/${address}/pockets`, options);

        return fetch(url)
          .then((resp) => {
            return Utils.handleFetchResponse(resp);
          })
          .catch((err) => {
            return Utils.handleFetchError(err, 'getAccountPockets');
          });
      });
  }

  getAccountPocket(gatewayAddress, address, currency) {
    return this.getDataApiUrl()
      .then((data_apiURL) => {
        const options = {
          counterparty: gatewayAddress,
          currency,
        };
        const url = Utils.addQueryString(`${data_apiURL}/accounts/${address}/pockets`, options);

        return fetch(url)
          .then((resp) => {
            return Utils.handleFetchResponse(resp);
          })
          .catch((err) => {
            return Utils.handleFetchError(err, 'getAccountPocket');
          });
      });
  }

  setPocket(sourceAccount, currency, frozen = false) {
    const pconfig = {
      method: 'POST',
      data: {
        address: sourceAccount.address,
        currency,
        frozen,
      },
    };

    const poptions = Utils.makeFetchRequestOptions(pconfig);
    return fetch(`${this.isunpayrpcURL}/prepareTrustline`, poptions)
      .then((resp) => {
        return Utils.handleFetchResponse(resp);
      })
      .then((prepared) => {
        const signedData = sign(prepared.txJSON, sourceAccount.secret);

        const config = {
          method: 'POST',
          data: {
            signed: signedData,
            maxLedgerVersion: prepared.instructions.maxLedgerVersion,
          },
        };

        const options = Utils.makeFetchRequestOptions(config);

        return fetch(`${this.isunpayrpcURL}/pocket`, options);
      })
      .then((resp) => {
        return Utils.handleFetchResponse(resp);
      })
      .then((data) => {
        return Promise.resolve(data);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'setPocket');
      });
  }
}
