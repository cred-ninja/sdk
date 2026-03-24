import { createHash, createPrivateKey, createPublicKey, randomBytes, sign } from 'node:crypto';

const ED25519_PRIVATE_KEY_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_PUBLIC_KEY_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export interface WebBotAuthSignerConfig {
  privateKeyHex: string;
  signatureAgent: string;
  ttlSeconds: number;
}

export interface WebBotAuthSigner {
  readonly keyId: string;
  readonly signatureAgent: string;
  signRequest(input: {
    url: string;
    method: string;
    headers?: Record<string, string>;
    now?: Date;
    nonce?: string;
  }): Record<string, string>;
}

export function createWebBotAuthSigner(config: WebBotAuthSignerConfig): WebBotAuthSigner {
  const privateKeyBytes = Buffer.from(config.privateKeyHex, 'hex');
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PRIVATE_KEY_PREFIX, privateKeyBytes]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey);
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const rawPublicKey = new Uint8Array(spki.slice(-32));
  const keyId = jwkThumbprint({
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(rawPublicKey).toString('base64url'),
  });

  return {
    keyId,
    signatureAgent: config.signatureAgent,
    signRequest(input) {
      const now = input.now ?? new Date();
      const created = Math.floor(now.getTime() / 1000);
      const expires = created + config.ttlSeconds;
      const nonce = input.nonce ?? randomBytes(12).toString('base64url');
      const authority = new URL(input.url).host;
      const signatureAgentValue = `"${config.signatureAgent}"`;
      const signatureParams = `("@authority" "signature-agent");created=${created};expires=${expires};nonce="${nonce}";alg="ed25519";keyid="${keyId}";tag="web-bot-auth"`;
      const signatureBase = [
        `"@authority": ${authority}`,
        `"signature-agent": ${signatureAgentValue}`,
        `"@signature-params": ${signatureParams}`,
      ].join('\n');

      const signature = sign(null, Buffer.from(signatureBase, 'utf8'), privateKey).toString('base64');

      return {
        ...(input.headers ?? {}),
        'Signature-Agent': signatureAgentValue,
        'Signature-Input': `sig1=${signatureParams}`,
        'Signature': `sig1=:${signature}:`,
      };
    },
  };
}

function jwkThumbprint(jwk: { kty: 'OKP'; crv: 'Ed25519'; x: string }): string {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
  });
  return createHash('sha256').update(canonical).digest('base64url');
}

export function rawPrivateKeyToPublicKeyHex(privateKeyHex: string): string {
  const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PRIVATE_KEY_PREFIX, privateKeyBytes]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey);
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return Buffer.concat([ED25519_PUBLIC_KEY_PREFIX, Buffer.from(spki.slice(-32))]).toString('hex');
}
