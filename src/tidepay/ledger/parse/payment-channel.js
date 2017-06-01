'use strict'; // eslint-disable-line strict

var _ = require('lodash');
var utils = require('./utils');

function parsePaymentChannel(data) {
  return utils.removeUndefined({
    account: data.Account,
    amount: utils.dropsToXrp(data.Amount),
    balance: utils.dropsToXrp(data.Balance),
    destination: data.Destination,
    publicKey: data.PublicKey,
    settleDelay: data.SettleDelay,
    expiration: utils.parseTimestamp(data.Expiration),
    cancelAfter: utils.parseTimestamp(data.CancelAfter),
    sourceTag: data.SourceTag,
    destinationTag: data.DestinationTag,
    previousAffectingTransactionID: data.PreviousTxnID,
    previousAffectingTransactionLedgerVersion: data.PreviousTxnLgrSeq
  });
}

module.exports = parsePaymentChannel;