import { importPKCS8 } from 'jose';
import { PingFederateExchange, type PingFederateConfig, type Dependencies } from './pingfederate.ts';
import { ExchangeError } from './token-exchange.ts';

// Inject env from a secret manager at startup. No committed keys or mock defaults.
export async function gateway2FromEnvironment(authorise: Dependencies['authorise'], observe?: Dependencies['observe'], env = process.env) {
  try {
    if (env.GATEWAY2_EXCHANGE_MODE !== 'production' || !env.PF_B_EXCHANGE_CONFIG || !env.PF_B_CLIENT_PRIVATE_KEY) throw Error();
    const config = JSON.parse(env.PF_B_EXCHANGE_CONFIG) as PingFederateConfig;
    const clientKey = await importPKCS8(env.PF_B_CLIENT_PRIVATE_KEY, config.clientAlgorithm);
    return new PingFederateExchange(config, { clientKey, authorise, observe });
  } catch { throw new ExchangeError('configuration'); }
}
