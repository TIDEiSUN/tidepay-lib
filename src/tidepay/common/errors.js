'use strict'; // eslint-disable-line strict

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var util = require('util');
var browserHacks = require('./browser-hacks');

// this is needed because extending builtins doesn't work in babel 6.x
function extendableBuiltin(cls) {
  function ExtendableBuiltin() {
    cls.apply(this, arguments);
  }
  ExtendableBuiltin.prototype = Object.create(cls.prototype);
  browserHacks.setPrototypeOf(ExtendableBuiltin, cls);
  return ExtendableBuiltin;
}

var RippleError = function (_extendableBuiltin) {
  _inherits(RippleError, _extendableBuiltin);

  function RippleError(message, data) {
    _classCallCheck(this, RippleError);

    var _this = _possibleConstructorReturn(this, (RippleError.__proto__ || Object.getPrototypeOf(RippleError)).call(this, message));

    _this.name = browserHacks.getConstructorName(_this);
    _this.message = message;
    _this.data = data;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(_this, _this.constructor.name);
    }
    return _this;
  }

  _createClass(RippleError, [{
    key: 'toString',
    value: function toString() {
      var result = '[' + this.name + '(' + this.message;
      if (this.data) {
        result += ', ' + util.inspect(this.data);
      }
      result += ')]';
      return result;
    }

    /* console.log in node uses util.inspect on object, and util.inspect allows
    us to cutomize its output:
    https://nodejs.org/api/util.html#util_custom_inspect_function_on_objects */

  }, {
    key: 'inspect',
    value: function inspect() {
      return this.toString();
    }
  }]);

  return RippleError;
}(extendableBuiltin(Error));

var RippledError = function (_RippleError) {
  _inherits(RippledError, _RippleError);

  function RippledError() {
    _classCallCheck(this, RippledError);

    return _possibleConstructorReturn(this, (RippledError.__proto__ || Object.getPrototypeOf(RippledError)).apply(this, arguments));
  }

  return RippledError;
}(RippleError);

var UnexpectedError = function (_RippleError2) {
  _inherits(UnexpectedError, _RippleError2);

  function UnexpectedError() {
    _classCallCheck(this, UnexpectedError);

    return _possibleConstructorReturn(this, (UnexpectedError.__proto__ || Object.getPrototypeOf(UnexpectedError)).apply(this, arguments));
  }

  return UnexpectedError;
}(RippleError);

var LedgerVersionError = function (_RippleError3) {
  _inherits(LedgerVersionError, _RippleError3);

  function LedgerVersionError() {
    _classCallCheck(this, LedgerVersionError);

    return _possibleConstructorReturn(this, (LedgerVersionError.__proto__ || Object.getPrototypeOf(LedgerVersionError)).apply(this, arguments));
  }

  return LedgerVersionError;
}(RippleError);

var ConnectionError = function (_RippleError4) {
  _inherits(ConnectionError, _RippleError4);

  function ConnectionError() {
    _classCallCheck(this, ConnectionError);

    return _possibleConstructorReturn(this, (ConnectionError.__proto__ || Object.getPrototypeOf(ConnectionError)).apply(this, arguments));
  }

  return ConnectionError;
}(RippleError);

var NotConnectedError = function (_ConnectionError) {
  _inherits(NotConnectedError, _ConnectionError);

  function NotConnectedError() {
    _classCallCheck(this, NotConnectedError);

    return _possibleConstructorReturn(this, (NotConnectedError.__proto__ || Object.getPrototypeOf(NotConnectedError)).apply(this, arguments));
  }

  return NotConnectedError;
}(ConnectionError);

var DisconnectedError = function (_ConnectionError2) {
  _inherits(DisconnectedError, _ConnectionError2);

  function DisconnectedError() {
    _classCallCheck(this, DisconnectedError);

    return _possibleConstructorReturn(this, (DisconnectedError.__proto__ || Object.getPrototypeOf(DisconnectedError)).apply(this, arguments));
  }

  return DisconnectedError;
}(ConnectionError);

var RippledNotInitializedError = function (_ConnectionError3) {
  _inherits(RippledNotInitializedError, _ConnectionError3);

  function RippledNotInitializedError() {
    _classCallCheck(this, RippledNotInitializedError);

    return _possibleConstructorReturn(this, (RippledNotInitializedError.__proto__ || Object.getPrototypeOf(RippledNotInitializedError)).apply(this, arguments));
  }

  return RippledNotInitializedError;
}(ConnectionError);

var TimeoutError = function (_ConnectionError4) {
  _inherits(TimeoutError, _ConnectionError4);

  function TimeoutError() {
    _classCallCheck(this, TimeoutError);

    return _possibleConstructorReturn(this, (TimeoutError.__proto__ || Object.getPrototypeOf(TimeoutError)).apply(this, arguments));
  }

  return TimeoutError;
}(ConnectionError);

var ResponseFormatError = function (_ConnectionError5) {
  _inherits(ResponseFormatError, _ConnectionError5);

  function ResponseFormatError() {
    _classCallCheck(this, ResponseFormatError);

    return _possibleConstructorReturn(this, (ResponseFormatError.__proto__ || Object.getPrototypeOf(ResponseFormatError)).apply(this, arguments));
  }

  return ResponseFormatError;
}(ConnectionError);

var ValidationError = function (_RippleError5) {
  _inherits(ValidationError, _RippleError5);

  function ValidationError() {
    _classCallCheck(this, ValidationError);

    return _possibleConstructorReturn(this, (ValidationError.__proto__ || Object.getPrototypeOf(ValidationError)).apply(this, arguments));
  }

  return ValidationError;
}(RippleError);

var NotFoundError = function (_RippleError6) {
  _inherits(NotFoundError, _RippleError6);

  function NotFoundError(message) {
    _classCallCheck(this, NotFoundError);

    return _possibleConstructorReturn(this, (NotFoundError.__proto__ || Object.getPrototypeOf(NotFoundError)).call(this, message || 'Not found'));
  }

  return NotFoundError;
}(RippleError);

var MissingLedgerHistoryError = function (_RippleError7) {
  _inherits(MissingLedgerHistoryError, _RippleError7);

  function MissingLedgerHistoryError(message) {
    _classCallCheck(this, MissingLedgerHistoryError);

    return _possibleConstructorReturn(this, (MissingLedgerHistoryError.__proto__ || Object.getPrototypeOf(MissingLedgerHistoryError)).call(this, message || 'Server is missing ledger history in the specified range'));
  }

  return MissingLedgerHistoryError;
}(RippleError);

var PendingLedgerVersionError = function (_RippleError8) {
  _inherits(PendingLedgerVersionError, _RippleError8);

  function PendingLedgerVersionError(message) {
    _classCallCheck(this, PendingLedgerVersionError);

    return _possibleConstructorReturn(this, (PendingLedgerVersionError.__proto__ || Object.getPrototypeOf(PendingLedgerVersionError)).call(this, message || 'maxLedgerVersion is greater than server\'s' + ' most recent validated ledger'));
  }

  return PendingLedgerVersionError;
}(RippleError);

module.exports = {
  RippleError: RippleError,
  UnexpectedError: UnexpectedError,
  ConnectionError: ConnectionError,
  RippledError: RippledError,
  NotConnectedError: NotConnectedError,
  DisconnectedError: DisconnectedError,
  RippledNotInitializedError: RippledNotInitializedError,
  TimeoutError: TimeoutError,
  ResponseFormatError: ResponseFormatError,
  ValidationError: ValidationError,
  NotFoundError: NotFoundError,
  PendingLedgerVersionError: PendingLedgerVersionError,
  MissingLedgerHistoryError: MissingLedgerHistoryError,
  LedgerVersionError: LedgerVersionError
};