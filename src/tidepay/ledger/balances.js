'use strict'; // eslint-disable-line strict

var utils = require('./utils');
var validate = utils.common.validate;


function getTrustlineBalanceAmount(trustline) {
  return {
    currency: trustline.specification.currency,
    counterparty: trustline.specification.counterparty,
    value: trustline.state.balance
  };
}

function formatBalances(options, balances) {
  var result = balances.trustlines.map(getTrustlineBalanceAmount);
  if (!(options.counterparty || options.currency && options.currency !== 'XTP')) {
    var xrpBalance = {
      currency: 'XTP',
      value: balances.xrp
    };
    result.unshift(xrpBalance);
  }
  if (options.limit && result.length > options.limit) {
    var toRemove = result.length - options.limit;
    result.splice(-toRemove, toRemove);
  }
  return result;
}

function getLedgerVersionHelper(connection, optionValue) {
  if (optionValue !== undefined && optionValue !== null) {
    return Promise.resolve(optionValue);
  }
  return connection.getLedgerVersion();
}

function getBalances(address) {
  var _this = this;

  var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

  validate.getTrustlines({ address: address, options: options });

  return Promise.all([getLedgerVersionHelper(this, options.ledgerVersion).then(function (ledgerVersion) {
    return utils.getXRPBalance(_this, address, ledgerVersion);
  }), this.getTrustlines(address, options)]).then(function (results) {
    return formatBalances(options, { xrp: results[0], trustlines: results[1] });
  });
}

module.exports = getBalances;