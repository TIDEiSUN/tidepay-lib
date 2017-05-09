'use strict';

function normalize(digitArray) {
  var i = 0;
  while (digitArray[i] === 0) {
    ++i;
  }
  if (i > 0) {
    digitArray.splice(0, i);
  }
  return digitArray;
}

function divmod(digitArray, base, divisor) {
  var remainder = 0;
  var temp = undefined,
      divided = undefined;
  var j = -1;

  var length = digitArray.length;
  var quotient = new Array(length);

  while (++j < length) {
    temp = remainder * base + digitArray[j];
    divided = temp / divisor;
    quotient[j] = divided << 0;
    remainder = temp % divisor;
  }
  return { quotient: normalize(quotient), remainder: remainder };
}

function convertBase(digitArray, fromBase, toBase) {
  var result = [];
  var dividend = digitArray,
      qr = undefined;
  while (dividend.length > 0) {
    qr = divmod(dividend, fromBase, toBase);
    result.unshift(qr.remainder);
    dividend = qr.quotient;
  }
  return normalize(result);
}

module.exports = convertBase;