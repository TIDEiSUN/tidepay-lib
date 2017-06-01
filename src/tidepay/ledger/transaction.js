'use strict'; // eslint-disable-line strict

var _ = require('lodash');
var utils = require('./utils');
var parseTransaction = require('./parse/transaction');
var _utils$common = utils.common,
    validate = _utils$common.validate,
    errors = _utils$common.errors;


function attachTransactionDate(api, tx) {
  if (tx.date) {
    return Promise.resolve(tx);
  }

  var ledgerVersion = tx.ledger_index || tx.LedgerSequence;

  if (!ledgerVersion) {
    return new Promise(function () {
      throw new errors.NotFoundError('ledger_index and LedgerSequence not found in tx');
    });
  }

  var request = {
    ledger_index: ledgerVersion
  };

  return api.doLedger(request).then(function (data) {
    if (typeof data.ledger.close_time === 'number') {
      return _.assign({ date: data.ledger.close_time }, tx);
    }
    throw new errors.UnexpectedError('Ledger missing close_time');
  }).catch(function (error) {
    if (error instanceof errors.UnexpectedError) {
      throw error;
    }
    throw new errors.NotFoundError('Transaction ledger not found');
  });
}

function isTransactionInRange(tx, options) {
  return (!options.minLedgerVersion || tx.ledger_index >= options.minLedgerVersion) && (!options.maxLedgerVersion || tx.ledger_index <= options.maxLedgerVersion);
}

function convertError(api, options, error) {
  var _error = error.message === 'txnNotFound' ? new errors.NotFoundError('Transaction not found') : error;
  if (_error instanceof errors.NotFoundError) {
    return utils.hasCompleteLedgerRange(api, options.minLedgerVersion, options.maxLedgerVersion).then(function (hasCompleteLedgerRange) {
      if (!hasCompleteLedgerRange) {
        return utils.isPendingLedgerVersion(api, options.maxLedgerVersion).then(function (isPendingLedgerVersion) {
          return isPendingLedgerVersion ? new errors.PendingLedgerVersionError() : new errors.MissingLedgerHistoryError();
        });
      }
      return _error;
    });
  }
  return Promise.resolve(_error);
}

function formatResponse(options, tx) {
  if (tx.validated !== true || !isTransactionInRange(tx, options)) {
    throw new errors.NotFoundError('Transaction not found');
  }
  return parseTransaction(tx);
}

function getTransaction(id) {
  var _this = this;

  var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

  validate.getTransaction({ id: id, options: options });

  var request = {
    transaction: id,
    binary: false
  };

  return utils.ensureLedgerVersion.call(this, options).then(function (_options) {
    return _this.doTx(request).then(function (tx) {
      return attachTransactionDate(_this, tx);
    }).then(_.partial(formatResponse, _options)).catch(function (error) {
      return convertError(_this, _options, error).then(function (_error) {
        throw _error;
      });
    });
  });
}

module.exports = getTransaction;