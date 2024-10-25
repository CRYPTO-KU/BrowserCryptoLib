import { UtilsError } from './errors';

export function getEnvironment(): string {
  if (
    typeof process !== 'undefined' &&
    process.versions != null &&
    process.versions.node != null
  ) {
    return 'node';
  }

  if (typeof window !== 'undefined' || typeof self !== 'undefined') {
    return 'web';
  }

  throw new UtilsError({
    name: 'UNDEFINED_ENVIRONMENT_ERROR',
    message: 'The environment (web or node.js) is not recognized',
  });
}
