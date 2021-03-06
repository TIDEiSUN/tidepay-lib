'use strict'; // eslint-disable-line strict

var _ = require('lodash');
var utils = require('./utils');
var validate = utils.common.validate;
var trustlineFlags = utils.common.txFlags.TrustSet;
var BigNumber = require('bignumber.js');


function convertQuality(quality) {
  return new BigNumber(quality).shift(9).truncated().toNumber();
}

function createTrustlineTransaction(account, trustline) {
  var limit = {
    currency: trustline.currency,
    issuer: trustline.counterparty,
    value: trustline.limit
  };

  var txJSON = {
    TransactionType: 'TrustSet',
    Account: account,
    LimitAmount: limit,
    Flags: 0
  };
  if (trustline.qualityIn !== undefined) {
    txJSON.QualityIn = convertQuality(trustline.qualityIn);
  }
  if (trustline.qualityOut !== undefined) {
    txJSON.QualityOut = convertQuality(trustline.qualityOut);
  }
  if (trustline.authorized === true) {
    txJSON.Flags |= trustlineFlags.SetAuth;
  }
  if (trustline.ripplingDisabled !== undefined) {
    txJSON.Flags |= trustline.ripplingDisabled ? trustlineFlags.NoRipple : trustlineFlags.ClearNoRipple;
  }
  if (trustline.frozen !== undefined) {
    txJSON.Flags |= trustline.frozen ? trustlineFlags.SetFreeze : trustlineFlags.ClearFreeze;
  }
  if (trustline.memos !== undefined) {
    txJSON.Memos = _.map(trustline.memos, utils.convertMemo);
  }
  return txJSON;
}

function prepareTrustline(address, trustline) {
  var instructions = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};

  validate.prepareTrustline({ address: address, trustline: trustline, instructions: instructions });
  var txJSON = createTrustlineTransaction(address, trustline);
  return utils.prepareTransaction(txJSON, this, instructions);
}

module.exports = prepareTrustline;