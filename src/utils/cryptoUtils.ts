import { getEnvironment } from './environment';
import { UtilsError } from './errors';

let cryptoAPI: Crypto | null = null;

async function initializeCryptoAPI(): Promise<void> {
  switch (getEnvironment()) {
    case 'node':
      const nodeCrypto = await import('crypto');
      cryptoAPI = nodeCrypto.webcrypto as Crypto;
      break;
    case 'web':
      cryptoAPI = typeof self !== 'undefined' ? self.crypto : window.crypto;
      break;
  }
}

export async function getCryptoAPI(): Promise<Crypto> {
  if (!cryptoAPI) {
    await initializeCryptoAPI();
  }
  if (!cryptoAPI) {
    throw new UtilsError({
      name: 'UNAVAILABLE_CRYPTO_ERROR',
      message: 'Crypto API is not available in this environment',
    });
  }
  return cryptoAPI;
}
