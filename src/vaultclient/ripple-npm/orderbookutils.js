'use strict';

var _ = require('lodash');
var assert = require('assert');
var SerializedObject = require('./serializedobject').SerializedObject;
var Types = require('./serializedtypes');
var Amount = require('./amount').Amount;
var Currency = require('./currency').Currency;
var UInt160 = require('./uint160').UInt160;

// const IOU_SUFFIX = '/000/rrrrrrrrrrrrrrrrrrrrrhoLvTp';
var IOU_SUFFIX_CURRENCY = Currency.from_json('000');
var IOU_SUFFIX_ISSUER = UInt160.from_json('rrrrrrrrrrrrrrrrrrrrrhoLvTp');
var OrderBookUtils = {};

function assertValidNumber(number, message) {
  assert(!_.isNull(number) && !isNaN(number), message);
}

function createAmount(number) {
  var amount = new Amount();
  amount.set_issuer(IOU_SUFFIX_ISSUER);
  amount._currency = IOU_SUFFIX_CURRENCY;
  amount.parse_value(number);

  return amount;
}

/**
 * Casts and returns offer's taker gets funded amount as a default IOU amount
 *
 * @param {Object} offer
 * @return {Amount}
 */

OrderBookUtils.getOfferTakerGetsFunded = function (offer) {
  assertValidNumber(offer.taker_gets_funded, 'Taker gets funded is invalid');

  return createAmount(offer.taker_gets_funded);
};

/**
 * Casts and returns offer's taker pays funded amount as a default IOU amount
 *
 * @param {Object} offer
 * @return {Amount}
 */

OrderBookUtils.getOfferTakerPaysFunded = function (offer) {
  assertValidNumber(offer.taker_pays_funded, 'Taker gets funded is invalid');

  return createAmount(offer.taker_pays_funded);
};

/**
 * Get offer taker gets amount
 *
 * @param {Object} offer
 *
 * @return {Amount}
 */

OrderBookUtils.getOfferTakerGets = function (offer) {
  assert(typeof offer, 'object', 'Offer is invalid');

  return createAmount(offer.TakerGets);
};

/**
 * Retrieve offer quality
 *
 * @param {Object} offer
 * @param {Currency} currencyGets
 */

OrderBookUtils.getOfferQuality = function (offer, currencyGets) {
  var amount = undefined;

  if (currencyGets.has_interest()) {
    // XXX Should use Amount#from_quality
    amount = Amount.from_json(offer.TakerPays).ratio_human(offer.TakerGets, {
      reference_date: new Date()
    });
  } else {
    amount = createAmount(offer.quality);
  }

  return amount;
};

/**
 * Formats an offer quality amount to a hex that can be parsed by
 * Amount.parse_quality
 *
 * @param {Amount} quality
 *
 * @return {String}
 */

OrderBookUtils.convertOfferQualityToHex = function (quality) {
  assert(quality instanceof Amount, 'Quality is not an amount');

  var so = new SerializedObject();
  Types.Quality.serialize(so, createAmount(quality.to_text()));

  return so.to_hex();
};

/**
 * Formats an offer quality amount to a hex that can be parsed by
 * Amount.parse_quality
 *
 * @param {String} quality
 *
 * @return {String}
 */

OrderBookUtils.convertOfferQualityToHexFromText = function (quality) {

  var so = new SerializedObject();
  Types.Quality.serialize(so, createAmount(quality));

  return so.to_hex();
};

/**
 *
 */

OrderBookUtils.normalizeAmount = function (value) {
  return createAmount(value);
};

module.exports = OrderBookUtils;