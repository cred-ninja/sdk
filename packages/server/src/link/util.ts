/**
 * Cred Link server: small shared helpers (ids, secrets, hashing, responses).
 */

import crypto from 'node:crypto';
import type { Request, Response } from 'express';
import {
  CRED_REQUEST_ID_HEADER,
  LINK_ID_PREFIXES,
  LINK_OPAQUE_FAILURE_BODY,
  LINK_OPAQUE_FAILURE_STATUS,
} from '@credninja/protocol';
import type { LinkErrorBody, LinkWireErrorCode } from '@credninja/protocol';

/** A new prefixed id: prefix + 32 hex characters (the repo's randomUUID-without-dashes convention). */
export function newId<P extends string>(prefix: P): `${P}${string}` {
  return `${prefix}${crypto.randomUUID().replace(/-/g, '')}` as `${P}${string}`;
}

/** 32 random bytes, base64url, no padding: LINK_SECRET_PATTERN. */
export function newSecret(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * The string without its trailing '/' characters. A linear scan: the
 * /\/+$/ regex backtracks quadratically on long runs of '/' that are not at
 * the end, and client assertion audiences reach this from the network.
 */
export function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0x2f) end -= 1;
  return end === value.length ? value : value.slice(0, end);
}

/** Lowercase hex SHA-256 of the UTF-8 string (LINK_SECRET_HASH_ALGORITHM). */
export function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

/** Constant-time comparison of two lowercase hex digests of equal expected length. */
export function hexDigestsEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  if (left.length !== 32 || right.length !== 32) {
    // Still spend the comparison so timing does not reveal the shape.
    crypto.timingSafeEqual(Buffer.alloc(32), Buffer.alloc(32));
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

/** Current time as ISO-8601 UTC. */
export function nowIso(nowMs: number = Date.now()): string {
  return new Date(nowMs).toISOString();
}

/** Per-request id (`req_...`), cached on the request and sent as Cred-Request-Id. */
export function requestId(req: Request, res: Response): string {
  const existing = (req as { credLinkRequestId?: string }).credLinkRequestId;
  if (existing) return existing;
  const id = newId(LINK_ID_PREFIXES.request);
  (req as { credLinkRequestId?: string }).credLinkRequestId = id;
  res.setHeader(CRED_REQUEST_ID_HEADER, id);
  return id;
}

/**
 * The one opaque failure (spec 5 Enumeration): byte-identical body, status
 * 401, a Cred-Request-Id header, nothing else that differs between causes.
 */
export function sendOpaqueFailure(req: Request, res: Response): void {
  requestId(req, res);
  res.setHeader('Cache-Control', 'no-store');
  res.status(LINK_OPAQUE_FAILURE_STATUS).json(LINK_OPAQUE_FAILURE_BODY);
}

/** A typed error body: `{ error, request_id, ...extra }`. `message` must be static text. */
export function sendLinkError(
  req: Request,
  res: Response,
  status: number,
  error: LinkWireErrorCode,
  extra: Omit<LinkErrorBody, 'error' | 'request_id'> = {},
): void {
  const id = requestId(req, res);
  res.setHeader('Cache-Control', 'no-store');
  const body: LinkErrorBody = { error, request_id: id, ...extra };
  res.status(status).json(body);
}

/** HTML escape for text and attribute values. */
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      default: return '&#39;';
    }
  });
}

/** JSON for embedding inside a `<script type="application/json">` data block. */
export function jsonForScriptBlock(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

/** True when the string has a C0/C1 control character or a Unicode line/paragraph separator. */
export function hasControlCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029) return true;
  }
  return false;
}

/** A bounded, printable, non-empty string, or null. */
export function boundedString(value: unknown, maxLength: number): string | null {
  if (typeof value !== 'string' || value === '' || value.length > maxLength || hasControlCharacter(value)) return null;
  return value;
}

/** First string value of a parsed query or form field (Express may give arrays). */
export function singleField(value: unknown): string | undefined | null {
  if (value === undefined) return undefined;
  if (typeof value === 'string') return value;
  return null;
}

/** All string values of a repeated form field. */
export function repeatedField(value: unknown): string[] {
  if (value === undefined) return [];
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  return [];
}

/** Parse the Cookie header into a map (first value wins). */
export function parseCookieHeader(header: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key && !out.has(key)) out.set(key, value);
  }
  return out;
}

/** Whether an http(s) URL host is loopback (localhost, 127.0.0.0/8, [::1]). */
export function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return h === 'localhost' || h === '[::1]' || h === '::1' || /^127(?:\.\d{1,3}){3}$/.test(h);
}

/** Origin of a URL string, or null. */
export function originOf(value: string): string | null {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}
