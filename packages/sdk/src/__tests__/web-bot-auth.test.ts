import { createPublicKey, generateKeyPairSync, verify as verifySignature } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createWebBotAuthSigner, rawPrivateKeyToPublicKeyHex } from '../web-bot-auth';

describe('createWebBotAuthSigner()', () => {
  it('signs requests with Cloudflare-compatible headers', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
    const privateKeyHex = pkcs8.slice(-32).toString('hex');

    const signer = createWebBotAuthSigner({
      privateKeyHex,
      signatureAgent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
      ttlSeconds: 60,
    });

    const headers = signer.signRequest({
      url: 'https://api.example.com/v1/resource',
      method: 'GET',
      now: new Date('2026-03-24T12:00:00.000Z'),
      nonce: 'fixed-nonce',
    });

    expect(headers['Signature-Agent']).toBe('"https://cred.example.com/.well-known/http-message-signatures-directory"');
    expect(headers['Signature-Input']).toContain('tag="web-bot-auth"');
    expect(headers['Signature-Input']).toContain('nonce="fixed-nonce"');
    expect(headers['Signature']).toMatch(/^sig1=:[^:]+:$/);
  });

  it('produces verifiable signatures', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
    const privateKeyHex = pkcs8.slice(-32).toString('hex');
    const publicKeyHex = rawPrivateKeyToPublicKeyHex(privateKeyHex);

    const signer = createWebBotAuthSigner({
      privateKeyHex,
      signatureAgent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
      ttlSeconds: 60,
    });

    const headers = signer.signRequest({
      url: 'https://api.example.com/v1/resource',
      method: 'GET',
      now: new Date('2026-03-24T12:00:00.000Z'),
      nonce: 'fixed-nonce',
    });

    const signatureInput = headers['Signature-Input'].replace(/^sig1=/, '');
    const signature = headers['Signature'].match(/^sig1=:([^:]+):$/)?.[1];
    expect(signature).toBeDefined();

    const publicKey = createPublicKey({
      key: Buffer.from(publicKeyHex, 'hex'),
      format: 'der',
      type: 'spki',
    });
    const valid = verifySignature(
      null,
      Buffer.from([
        '"@authority": api.example.com',
        '"signature-agent": "https://cred.example.com/.well-known/http-message-signatures-directory"',
        `"@signature-params": ${signatureInput}`,
      ].join('\n'), 'utf8'),
      publicKey,
      Buffer.from(signature!, 'base64'),
    );

    expect(valid).toBe(true);
  });
});
