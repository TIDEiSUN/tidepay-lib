'use strict'; // eslint-disable-line strict

var utils = require('../utils');


function parseAmount(amount) {
  if (typeof amount === 'string') {
    return {
      currency: 'XTP',
      value: utils.common.dropsToXrp(amount)
    };
  }
  return {
    currency: amount.currency,
    value: amount.value,
    counterparty: amount.issuer
  };
}

module.exports = parseAmount;