import fetch from 'isomorphic-fetch';
import { w3cwebsocket as W3CWebSocket } from 'websocket';
import Utils from '../common/utils';
import generateAddressAPI from './offline/generate-address'
import preparePayment from './transaction/payment';
import prepareSettings from './transaction/settings';
import submit from './transaction/submit';
import prepareTrustline from './transaction/trustline';

export default class TidePayDAPIClass {
  constructor(url) {
    // basic
    this.tidepaydURL = `${url}/`;

    // websocket
    this.ws = null;
    this.notifyTransactionCallback = null;
    this._ledgerVersion = null;
    this._fee_base = null;
    this._fee_ref = null;

    // rpc
    this._feeCushion = 1.2;
    this.preparePayment = preparePayment;
    this.prepareSettings = prepareSettings;
    this.prepareTrustline = prepareTrustline;
    this.generateAddress = generateAddressAPI;
    this.submit = submit;
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
  doAccountInfo(params) {
    const options = TidePayDAPIClass.buildOptions('account_info', params);
    return fetch(this.tidepaydURL, options).then(resp => Utils.handleFetchResponse(resp));
  }
  doAccountLines(params) {
    const options = TidePayDAPIClass.buildOptions('account_lines', params);
    return fetch(this.tidepaydURL, options).then(resp => Utils.handleFetchResponse(resp));
  }
  doLedger(params) {
    const options = TidePayDAPIClass.buildOptions('ledger', params);
    return fetch(this.tidepaydURL, options).then(resp => Utils.handleFetchResponse(resp));
  }
  doNorippleCheck(params) {
    const options = TidePayDAPIClass.buildOptions('noripple_check', params);
    return fetch(this.tidepaydURL, options).then(resp => Utils.handleFetchResponse(resp));
  }
  doRandom() {
    const options = TidePayDAPIClass.buildOptions('random', {});
    return fetch(this.tidepaydURL, options).then(resp => Utils.handleFetchResponse(resp));
  }
  doServerInfo() {
    const options = TidePayDAPIClass.buildOptions('server_info', {});
    return fetch(this.tidepaydURL, options).then(resp => Utils.handleFetchResponse(resp));
  }
  doSubmit(params) {
    const options = TidePayDAPIClass.buildOptions('submit', params);
    return fetch(this.tidepaydURL, options).then(resp => Utils.handleFetchResponse(resp));
  }
  connectWebsocket(options) {
    // TODO: review on options
    const { wsPath, wsReconnectInterval, logger } = options;
    this.ws = new W3CWebSocket(wsPath);
    this.ws.onopen = () => {
      const message = {
        id: 'Gateway monitor',
        command: 'subscribe',
        streams: ['ledger', 'transactions'],
      };
      try {
        this.ws.send(JSON.stringify(message));
      } catch (e) { logger.error(e); }
    };
    this.ws.onclose = () => {
      logger.info('Last ledger:', this._ledgerVersion);
      logger.info('ws closed');
      // TODO: queue task to open the websocket again
      setTimeout(() => {
        logger.info('ws reconnect');
        this.connectWebsocket(options);
      }, wsReconnectInterval);
    };
    this.ws.onmessage = (e) => {
      const jsondata = JSON.parse(e.data);
      switch (jsondata.type) {
        case 'ledgerClosed': {
          if (!this._ledgerVersion) {
            logger.info('First ledger:', jsondata.ledger_index);
          }
          this._ledgerVersion = Number(jsondata.ledger_index);
          this._fee_base = Number(jsondata.fee_base);
          this._fee_ref = Number(jsondata.fee_ref);
          break;
        }
        case 'response': {
          logger.debug('ws response message:', jsondata);
          if (jsondata.id === 'New transaction' && jsondata.status === 'success') {
            if (this.notifyTransactionCallback instanceof Function) {
              this.notifyTransactionCallback(jsondata.result);
            }
          }
          break;
        }
        case 'transaction': {
          logger.info('ws transaction message:', jsondata);
          const request = {
            id: 'New transaction',
            command: 'tx',
            transaction: jsondata.transaction.hash,
            binary: false,
          };
          this.ws.send(JSON.stringify(request));
          break;
        }
        default: {
          logger.info('ws other message:', jsondata);
          break;
        }
      }
    };
    this.ws.onerror = () => {
      logger.error('ws error:');
    };
  }
  getLedgerVersion() {
    return Promise.resolve(this._ledgerVersion);
  }
  getFeeBase() {
    return Promise.resolve(this._fee_base);
  }
  getFeeRef() {
    return Promise.resolve(this._fee_ref);
  }
}
