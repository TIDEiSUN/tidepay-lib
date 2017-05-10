import Utils from '../vaultclient/utils';
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
    return fetch(this.isunpayrpcURL + '/tidepayurl')
      .then((res) => {
        return res.json();
      })
      .then((value) => {
        this.dataapiURL = value.dataapi;
        console.log('data api url', this.dataapiURL);
        return Promise.resolve(this.dataapiURL);
      })
      .catch((err) => {
        console.error('Failed to get data api url', err);
        return Promise.reject(err);
      });
  }

  getGatewayAddress() {
    return fetch(this.isunpayrpcURL + '/gatewayaddress')
    .then((res) => {
      return res.json();
    })
  }

  getCurrencies() {
    return fetch(this.isunpayrpcURL + '/currency')
    .then((res) => {
      return res.json();
    })
  }

  /**
   * Get the latest withdrawal fee
   * @param {String} currency Currency to query (3-letter code)
   */
  getWithdrawalFee(currency = null) {
    const qs = { currency };
    const url = Utils.addQueryString(`${this.isunpayrpcURL}/withdrawalfee`, qs);
    console.log('getWithdrawalFee', url);
    return fetch(url)
    .then((res) => {
      return Utils.handleFetchResponse(res);
    });
  }

  /**
   * Get the latest exchange rate
   * @param {String} base Base currency (3-letter code)
   * @param {String|Array} symbols Limit results to specific currencies (3-letter codes)
   */
  getExchangeRate(base = null, symbols = null) {
    const qs = { base, symbols };
    const url = Utils.addQueryString(`${this.isunpayrpcURL}/exchangerate`, qs);
    console.log('getExchangeRate', url);
    return fetch(url)
    .then((res) => {
      return Utils.handleFetchResponse(res);
    });
  }

  getAccountBalances(address, options = {}) {
    return this.getDataApiUrl()
      .then((data_apiURL) => {
        let url = `${data_apiURL}/accounts/${address}/balances`

        if (options.currency) {
          url = `${url}?currency=${options.currency}`
        }

        return fetch(url).then((resp) => {
          return resp.json()
        }).then((json)=>{
          return json.result
        })
      });
  }

  getAccountTransactions(myAddress, options = {}) {
    return this.getDataApiUrl()
      .then((data_apiURL) => {
        let url = `${data_apiURL}/accounts/${myAddress}/transactions?type=Payment&descending=true&result=tesSUCCESS`
        if (options.currency) {
          url = `${url}&currency=${options.currency}`
        }
        return fetch(url).then((resp) => {
          return resp.json();
        })
      });
  }
  
  sendPayment(sourceAccount, payment) {
    const pconfig = {
      method: 'POST',
      data: payment
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

  sendInternalPayment(gatewayAddress, sourceAccount, destinationRippleAddress, currency, value) {
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
        address: destinationRippleAddress,
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
        let url=`${data_apiURL}/getPockets`
        let body = {
          "params": {
            "account": address,
            "ledger": "current"
          }
        }
        console.log(body)
        return fetch(url, {
          method:'post',
          headers: new Headers({
            'Content-Type': 'application/json'
          }),
          body:JSON.stringify(body)
        }).then(resp=>{
          return resp.json()
        })
      });
  }

  getAccountPocket(gatewayAddress, address, currency) {
    return this.getDataApiUrl()
      .then((data_apiURL) => {
        const options = {
          counterparty: gatewayAddress,
          currency,
        };
        let url=`${data_apiURL}/getPockets`
        let body = {
          "params": {
            "account": address,
            "ledger": "current",
            "currency":currency
          }
        }
        console.log(body)
        return fetch(url, {
          method:'post',
          headers: new Headers({
            'Content-Type': 'application/json'
          }),
          body:JSON.stringify(body)
        }).then(resp=>{
          return resp.json()
        })
      });
  }

  addPocket(gatewayAddress, sourceAccount, currency) {
    return this.setPocket(gatewayAddress, sourceAccount, currency, false);
  }

  setPocket(gatewayAddress, sourceAccount, currency, frozen = false) {
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
