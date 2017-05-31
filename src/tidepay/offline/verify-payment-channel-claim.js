'use strict'; // eslint-disable-line strict

var common = require('../common');
var keypairs = require('ripple-keypairs');
var binary = require('ripple-binary-codec');
var validate = common.validate,
    xrpToDrops = common.xrpToDrops;


function verifyPaymentChannelClaim(channel, amount, signature, publicKey) {
  validate.verifyPaymentChannelClaim({ channel: channel, amount: amount, signature: signature, publicKey: publicKey });

  var signingData = binary.encodeForSigningClaim({
    channel: channel,
    amount: xrpToDrops(amount)
  });
  return keypairs.verify(signingData, signature, publicKey);
}

module.exports = verifyPaymentChannelClaim;