import VaultClientClass, { Errors } from './vaultclient/VaultClient';
import TidePayAPIClass from './tidepay/TidePayAPI';

const VaultClient = new VaultClientClass(Config.isunpayrpcURL);
const TidePayAPI = new TidePayAPIClass(Config.isunpayrpcURL);

export default {
  VaultClient,
  TidePayAPI,
  Errors,
};

export {
  VaultClient,
  TidePayAPI,
  Errors,
};
