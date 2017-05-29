'use strict'; // eslint-disable-line strict

var _ = require('lodash');

var _require = require('./utils'),
    convertKeysFromSnakeCaseToCamelCase = _require.convertKeysFromSnakeCaseToCamelCase;

function renameKeys(object, mapping) {
  _.forEach(mapping, function (to, from) {
    object[to] = object[from];
    delete object[from];
  });
}

function getServerInfo(connection) {
  return connection.request({ command: 'server_info' }).then(function (response) {
    var info = convertKeysFromSnakeCaseToCamelCase(response.info);
    renameKeys(info, { hostid: 'hostID' });
    if (info.validatedLedger) {
      renameKeys(info.validatedLedger, {
        baseFeeXrp: 'baseFeeXRP',
        reserveBaseXrp: 'reserveBaseXRP',
        reserveIncXrp: 'reserveIncrementXRP',
        seq: 'ledgerVersion'
      });
      info.validatedLedger.baseFeeXRP = info.validatedLedger.baseFeeXRP.toString();
      info.validatedLedger.reserveBaseXRP = info.validatedLedger.reserveBaseXRP.toString();
      info.validatedLedger.reserveIncrementXRP = info.validatedLedger.reserveIncrementXRP.toString();
    }
    return info;
  });
}

function computeFeeFromServerInfo(cushion, serverInfo) {
  return (Number(serverInfo.validatedLedger.baseFeeXRP) * Number(serverInfo.loadFactor) * cushion).toString();
}

function getFee(connection, cushion) {
  return getServerInfo(connection).then(_.partial(computeFeeFromServerInfo, cushion));
}

module.exports = {
  getServerInfo: getServerInfo,
  getFee: getFee
};