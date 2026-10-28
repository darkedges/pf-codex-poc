import { ExchangeError, type TokenExchanger } from './token-exchange.ts';
import type { PingFederateConfig, Dependencies } from './pingfederate.ts';

// Dynamic imports keep the demo dependency-free; a production failure never selects mock.
export async function createGateway2Exchange(options:
  { mode: 'mock' } | { mode: 'production'; config: PingFederateConfig; dependencies: Dependencies }
): Promise<TokenExchanger> {
  if (options.mode === 'production') {
    const { PingFederateExchange } = await import('./pingfederate.ts');
    return new PingFederateExchange(options.config, options.dependencies);
  }
  if (options.mode !== 'mock' || process.env.DEMO_ONLY !== 'true' || process.env.NODE_ENV === 'production') throw new ExchangeError('configuration');
  const { MockGateway2Exchange } = await import('./mock-gateway-2.ts');
  return new MockGateway2Exchange();
}
