import fetch from 'isomorphic-fetch';
import { w3cwebsocket as W3CWebSocket } from 'websocket';
import Utils from '../common/utils';
import generateAddressAPI from './offline/generate-address';
import preparePayment from './transaction/payment';
import prepareSettings from './transaction/settings';
import sign from './transaction/sign';
import submit from './transaction/submit';
import prepareTrustline from './transaction/trustline';
import errors from './common/errors';
import RangeSet from './common/rangeset';

export default class TidePayDAPIClass {
  constructor(url) {
    // basic
    this.tidepaydURL = `${url}/`;

    // websocket
    this.ws = null;
    this.notifyTransactionCallback = null;
    this._ledgerVersion = null;
    this._availableLedgerVersions = new RangeSet();
    this._fee_base = null;
    this._fee_ref = null;

    // rpc
    this._feeCushion = 1.2;
    this.preparePayment = preparePayment;
    this.prepareSettings = prepareSettings;
    this.prepareTrustline = prepareTrustline;
    this.generateAddress = generateAddressAPI;
    this.sign = sign;
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
  static handleResponse(response) {
    return Utils.handleFetchResponse(response)
      .then((json) => {
        if (json.result.status === 'error') {
          return Promise.reject(new errors.RippledError(json.result.error));
        } else if (json.result.status === 'success') {
          return Promise.resolve(json.result);
        }
        return Promise.reject(new errors.ResponseFormatError(`unrecognized status: ${json.result.status}`));
      });
  }
  doAccountInfo(params) {
    const options = TidePayDAPIClass.buildOptions('account_info', params);
    return fetch(this.tidepaydURL, options).then(resp => TidePayDAPIClass.handleResponse(resp));
  }
  doAccountLines(params) {
    const options = TidePayDAPIClass.buildOptions('account_lines', params);
    return fetch(this.tidepaydURL, options).then(resp => TidePayDAPIClass.handleResponse(resp));
  }
  doLedger(params) {
    const options = TidePayDAPIClass.buildOptions('ledger', params);
    return fetch(this.tidepaydURL, options).then(resp => TidePayDAPIClass.handleResponse(resp));
  }
  doNorippleCheck(params) {
    const options = TidePayDAPIClass.buildOptions('noripple_check', params);
    return fetch(this.tidepaydURL, options).then(resp => TidePayDAPIClass.handleResponse(resp));
  }
  doRandom() {
    const options = TidePayDAPIClass.buildOptions('random', {});
    return fetch(this.tidepaydURL, options).then(resp => TidePayDAPIClass.handleResponse(resp));
  }
  doServerInfo() {
    const options = TidePayDAPIClass.buildOptions('server_info', {});
    return fetch(this.tidepaydURL, options).then(resp => TidePayDAPIClass.handleResponse(resp));
  }
  doSubmit(params) {
    const options = TidePayDAPIClass.buildOptions('submit', params);
    return fetch(this.tidepaydURL, options).then(resp => TidePayDAPIClass.handleResponse(resp));
  }
  doTx(params) {
    const options = TidePayDAPIClass.buildOptions('tx', params);
    return fetch(this.tidepaydURL, options).then(resp => TidePayDAPIClass.handleResponse(resp));
  }
  webSocketState() {
    const websocketStatus = ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'];
    return {
      websocket: websocketStatus[this.ws.readyState],
    };
  }
  connectWebsocket(options) {
    // TODO: review on options
    const { wsPath, wsReconnectInterval, logger } = options;
    this.ws = new W3CWebSocket(wsPath);
    this.ws.onopen = () => {
      logger.debug('tidepay-lib ws onopen');
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
      logger.debug('tidepay-lib ws onclose');
      logger.info('Last ledger:', this._ledgerVersion);
      // TODO: queue task to open the websocket again
      setTimeout(() => {
        logger.info('ws reconnect');
        this.connectWebsocket(options);
      }, wsReconnectInterval);
    };
    this.ws.onmessage = (e) => {
      // logger.debug('tidepay-lib ws onmessage:', e.data);
      const jsondata = JSON.parse(e.data);
      switch (jsondata.type) {
        case 'ledgerClosed': {
          if (!this._ledgerVersion) {
            logger.info('First ledger:', jsondata.ledger_index);
          }
          // update ledger version
          this._ledgerVersion = Number(jsondata.ledger_index);
          if (jsondata.validated_ledgers) {
            this._availableLedgerVersions.reset();
            this._availableLedgerVersions.parseAndAddRanges(jsondata.validated_ledgers);
          } else {
            this._availableLedgerVersions.addValue(this._ledgerVersion);
          }
          // update fee
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
      logger.error('tidepay-lib ws onerror');
    };
  }
  disconnectWebsocket() {
    logger.info('Last ledger:', this._ledgerVersion);
    this._ledgerVersion = null;
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
  getLedgerVersion() {
    return Promise.resolve(this._ledgerVersion);
  }
  hasLedgerVersions(lowLedgerVersion, highLedgerVersion) {
    return Promise.resolve(this._availableLedgerVersions.containsRange(lowLedgerVersion, highLedgerVersion || this._ledgerVersion));
  }
  getFeeBase() {
    return Promise.resolve(this._fee_base);
  }
  getFeeRef() {
    return Promise.resolve(this._fee_ref);
  }
}

export { errors };
