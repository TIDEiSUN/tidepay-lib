import fetch from 'isomorphic-fetch';
import WebSocket from 'ws';
import Utils from '../common/utils';
import generateAddressAPI from 'offline/generate-address'
import preparePayment from 'transaction/payment';
import prepareSettings from 'transaction/settings';
import prepareTrustline from 'transaction/trustline';

export default class TidePayAPIDClass {
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
    this.feeCushion = 1.2;
    this.preparePayment = preparePayment;
    this.prepareSettings = prepareSettings;
    this.prepareTrustline = prepareTrustline;
    this.generateAddress = generateAddressAPI;
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
  accountInfo(params) {
    const options = TidePayAPIDClass.buildOptions('account_info', params);
    return fetch(this.tidepaydURL, options)
      .then(resp => Utils.handleFetchResponse(resp));
  }
  accountLines(params) {
    const options = TidePayAPIDClass.buildOptions('account_lines', params);
    return fetch(this.tidepaydURL, options)
      .then(resp => Utils.handleFetchResponse(resp));
  }
  ledger(params) {
    const options = TidePayAPIDClass.buildOptions('ledger', params);
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
  serverInfo() {
    const options = TidePayAPIDClass.buildOptions('server_info', {});
    return fetch(this.tidepaydURL, options)
      .then(resp => Utils.handleFetchResponse(resp));
  }

  connectWebsocket(options) {
    // TODO: review on options
    const { wsPath, wsReconnectInterval, logger } = options;
    this.ws = new WebSocket(wsPath);
    this.ws.on('open', () => {
      const message = {
        id: 'Gateway monitor',
        command: 'subscribe',
        streams: ['ledger', 'transactions'],
      };
      try {
        this.ws.send(JSON.stringify(message));
      } catch (e) { logger.error(e); }
    });
    this.ws.on('close', (data) => {
      logger.info('Last ledger:', this._ledgerVersion);
      logger.info('ws closed:', data);
      // TODO: queue task to open the websocket again
      setTimeout(() => {
        logger.info('ws reconnect');
        this.connectWebsocket(options);
      }, wsReconnectInterval);
    });
    this.ws.on('message', (data) => {
      const jsondata = JSON.parse(data);
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
    });
    this.ws.on('error', (err) => {
      logger.error('ws error:', err);
    });
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
