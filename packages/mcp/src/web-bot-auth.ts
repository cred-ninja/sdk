import {
  createWebBotAuthSigner as createSdkWebBotAuthSigner,
  rawPrivateKeyToPublicKeyHex,
} from '@credninja/sdk';
import type { CredMcpWebBotAuthConfig } from './config.js';

export interface WebBotAuthSigner {
  readonly keyId: string;
  readonly signatureAgent: string;
  signRequest(input: {
    url: string;
    method: string;
    headers?: Record<string, string>;
    now?: Date;
  }): Record<string, string>;
}

export function createWebBotAuthSigner(config: CredMcpWebBotAuthConfig): WebBotAuthSigner {
  return createSdkWebBotAuthSigner({
    privateKeyHex: config.privateKeyHex,
    signatureAgent: config.signatureAgent,
    ttlSeconds: config.ttlSeconds,
  });
}
