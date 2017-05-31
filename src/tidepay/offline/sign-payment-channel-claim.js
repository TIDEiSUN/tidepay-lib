'use strict'; // eslint-disable-line strict

var common = require('../common');
var keypairs = require('../tidepay-keypairs');
var binary = require('../tidepay-binary-codec');
var validate = common.validate,
    xrpToDrops = common.xrpToDrops;


function signPaymentChannelClaim(channel, amount, privateKey) {
  validate.signPaymentChannelClaim({ channel: channel, amount: amount, privateKey: privateKey });

  var signingData = binary.encodeForSigningClaim({
    channel: channel,
    amount: xrpToDrops(amount)
  });
  return keypairs.sign(signingData, privateKey);
}

module.exports = signPaymentChannelClaim;