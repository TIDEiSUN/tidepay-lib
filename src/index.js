import VaultClientClass, { Utils, Errors } from './vaultclient/VaultClient';
import TidePayAPIClass from './tidepay/TidePayAPI';
import TidePayDAPIClass from './tidepay/TidePayDAPI';
import WAValidator from './cryptovalidator/wallet_address_validator';

export default {
  VaultClientClass,
  TidePayAPIClass,
  TidePayDAPIClass,
  WAValidator,
  Utils,  
  Errors,
};

export {
  VaultClientClass,
  TidePayAPIClass,
  TidePayDAPIClass,
  WAValidator,
  Utils,
  Errors,
};
