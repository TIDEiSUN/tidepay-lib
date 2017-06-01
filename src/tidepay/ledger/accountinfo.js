'use strict'; // eslint-disable-line strict

var utils = require('./utils');
var _utils$common = utils.common,
    validate = _utils$common.validate,
    removeUndefined = _utils$common.removeUndefined;


function formatAccountInfo(response) {
  var data = response.account_data;
  return removeUndefined({
    sequence: data.Sequence,
    xrpBalance: utils.common.dropsToXrp(data.Balance),
    ownerCount: data.OwnerCount,
    previousInitiatedTransactionID: data.AccountTxnID,
    previousAffectingTransactionID: data.PreviousTxnID,
    previousAffectingTransactionLedgerVersion: data.PreviousTxnLgrSeq
  });
}

function getAccountInfo(address) {
  var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

  validate.getAccountInfo({ address: address, options: options });

  var request = {
    account: address,
    ledger_index: options.ledgerVersion || 'validated'
  };

  return this.doAccountInfo(request).then(formatAccountInfo);
}

module.exports = getAccountInfo;