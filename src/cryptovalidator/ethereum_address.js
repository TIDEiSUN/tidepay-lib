(function (isNode) {
    var cryptoUtils;

    if (isNode) {
        cryptoUtils = require('./crypto_utils');
    } else {
        var imports = window.WAValidator.__imports;
        cryptoUtils = imports.cryptoUtils;
    }

    /**
     * Checks if the given string is a checksummed address
     *
     * @method isChecksumAddress
     * @param {String} address the given HEX adress
     * @return {Boolean}
    */
    function isChecksumAddress(address) {
        // Check each case
        address = address.replace('0x', '');
        var addressHash = cryptoUtils.keccak256(address.toLowerCase());

        for (var i = 0; i < 40; i++) {
            // the nth letter should be uppercase if the nth digit of casemap is 1
            if ((parseInt(addressHash[i], 16) > 7 && address[i].toUpperCase() !== address[i]) || (parseInt(addressHash[i], 16) <= 7 && address[i].toLowerCase() !== address[i])) {
                return false;
            }
        }
        return true;
    }

    var ethereumAddress = {
        /**
         * Checks if the given string is an address
         *
         * @method isAddress
         * @param {String} address the given HEX adress
         * @return {Boolean}
        */
        isAddress: function (address) {
            if (!/^(0x)?[0-9a-f]{40}$/i.test(address)) {
                // check if it has the basic requirements of an address
                return false;
            } else if (/^(0x)?[0-9a-f]{40}$/.test(address) || /^(0x)?[0-9A-F]{40}$/.test(address)) {
                // If it's all small caps or all all caps, return true
                return true;
            } else {
                // Otherwise check each case
                return isChecksumAddress(address);
            }
        }
    }
    // export ethereumAddress module
    if (isNode) {
        module.exports = ethereumAddress;
    } else {
        if (typeof window.WAValidator === 'undefined') {
            window.WAValidator = { __imports: {} };
        }
        window.WAValidator.__imports.ethereumAddress = ethereumAddress;
    }
})(typeof module !== 'undefined' && typeof module.exports !== 'undefined');