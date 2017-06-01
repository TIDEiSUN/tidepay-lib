'use strict'; // eslint-disable-line strict

var BigNumber = require('bignumber.js');

var _require = require('./utils'),
    dropsToXrp = _require.dropsToXrp;

function parseFeeUpdate(tx) {
  var baseFeeDrops = new BigNumber(tx.BaseFee, 16).toString();
  return {
    baseFeeXRP: dropsToXrp(baseFeeDrops),
    referenceFeeUnits: tx.ReferenceFeeUnits,
    reserveBaseXRP: dropsToXrp(tx.ReserveBase),
    reserveIncrementXRP: dropsToXrp(tx.ReserveIncrement)
  };
}

module.exports = parseFeeUpdate;