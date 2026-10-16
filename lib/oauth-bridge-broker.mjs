/**
 * Short-lived, one-time PKCE exchange broker between an existing Tesla relay
 * callback and a future private Sites backend.
 *
 * This is the SERVER-SIDE exchange primitive, not an HTTP endpoint. Its issue()
 * method MUST only be called inside the relay after successful Tesla owner
 * OAuth consent and token exchange. Never expose issue() as an MCP tool.
 *
 * Provide a durable shared ticketStore (Redis/SQL) with:
 *   put(hash, encryptedRecord, ttlSeconds): Promise<void>
 *   take(hash): Promise<encryptedRecord|null>  // atomic one-time remove
 * 'take' MUST be atomic across all relay replicas, and must enforce TTL.
 */
import {createHash, randomBytes, timingSafeEqual, createCipheriv, createDecipheriv} from 'node:crypto';

const sha = s => createHash('sha256').update(s, 'ascii').digest();
const credentialOk = s => typeof s === 'string' && /^[A-Za-z0-9_-]{32,20000}$/.test(s);
const codeOk = s => typeof s === 'string' && /^[A-Za-z0-9_-]{43}$/.test(s);
const challengeOk = codeOk;
const stateOk = s => typeof s === 'string' && /^[A-Za-z0-9_-]{32,256}$/.test(s);
const verifierOk = s => typeof s === 'string' && /^[A-Za-z0-9._~-]{43,128}$/.test(s);
export class TeslaLinkError extends Error {
  constructor(code) { super(code); this.name = 'TeslaLinkError'; this.code = code; }
}
const fail = c => {throw new TeslaLinkError(c)};
export const newPkceVerifier = () => randomBytes(32).toString('base64url');
export const pkceChallenge = verifier => {
  if (!verifierOk(verifier)) fail('invalid_pkce_verifier');
  return sha(verifier).toString('base64url');
};

const parseKey = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) fail('ticket_key_invalid');
  const key = Buffer.from(value, 'base64url');
  if (key.length !== 32 || key.toString('base64url') !== value) fail('ticket_key_invalid');
  return key;
};
const ticketAad = hash => Buffer.from('tesla-link-ticket-v1:' + hash, 'utf8');
function sealTicket(key, hash, payload) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(ticketAad(hash));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload)), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
}
function unsealTicket(key, hash, sealed) {
  try {
    if (typeof sealed !== 'string' || sealed.length > 30000) fail('authorization_code_invalid');
    const data = Buffer.from(sealed, 'base64url');
    if (data.length < 29) fail('authorization_code_invalid');
    const decipher = createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
    decipher.setAAD(ticketAad(hash));
    decipher.setAuthTag(data.subarray(12, 28));
    return JSON.parse(Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8'));
  } catch {fail('authorization_code_invalid');}
}

export function createTeslaLinkBroker({ticketStore, allowedSiteCallback, ticketKeyBase64url,
                                       clock = () => Date.now(), ttlSeconds = 90}) {
  const key = parseKey(ticketKeyBase64url);
  if (!ticketStore || typeof ticketStore.put !== 'function' || typeof ticketStore.take !== 'function') {
    fail('ticket_store_required');
  }
  let url;
  try { url = new URL(allowedSiteCallback); }
  catch {fail('invalid_callback_configuration')}
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search ||
      url.port || !url.hostname || !url.pathname.startsWith('/')) fail('invalid_callback_configuration');
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 30 || ttlSeconds > 300) fail('invalid_ticket_lifetime');
  const allowed = url.toString();

  return Object.freeze({
    /** Call ONLY from an authenticated Tesla relay callback after owner consent. */
    async issue({bridgeCredential, codeChallenge, state, redirectUri} = {}) {
      if (!credentialOk(bridgeCredential) || !challengeOk(codeChallenge) || !stateOk(state) ||
          redirectUri !== allowed) fail('invalid_authorization_request');
      const code = randomBytes(32).toString('base64url');
      const ticketKey = sha(code).toString('hex');
      const payload = {
        bridgeCredential, codeChallenge, redirectUri,
        expiresAt: clock() + ttlSeconds * 1000
      };
      try { await ticketStore.put(ticketKey, {sealed:sealTicket(key, ticketKey, payload)}, ttlSeconds); }
      catch {fail('authorization_store_unavailable')}
      const callback = new URL(allowed);
      callback.searchParams.set('code', code);
      callback.searchParams.set('state', state);
      return {callbackUrl: callback.toString()};
    },
    /** Call ONLY server-to-server from the Site after validating its own OAuth state. */
    async redeem({code, codeVerifier, redirectUri} = {}) {
      if (!codeOk(code) || !verifierOk(codeVerifier) || redirectUri !== allowed) {
        fail('authorization_code_invalid');
      }
      let value;
      const ticketKey = sha(code).toString('hex');
      try { value = await ticketStore.take(ticketKey); }
      catch {fail('authorization_store_unavailable')}
      if (!value || typeof value.sealed !== 'string') fail('authorization_code_invalid');
      value = unsealTicket(key, ticketKey, value.sealed);
      if (!value || typeof value.expiresAt !== 'number' || value.expiresAt <= clock() ||
          value.redirectUri !== allowed || !credentialOk(value.bridgeCredential) ||
          !challengeOk(value.codeChallenge)) fail('authorization_code_invalid');
      const suppliedChallenge = sha(codeVerifier);
      const targetChallenge = Buffer.from(value.codeChallenge, 'base64url');
      if (targetChallenge.length !== suppliedChallenge.length ||
          !timingSafeEqual(targetChallenge, suppliedChallenge)) fail('authorization_code_invalid');
      return {bridgeCredential: value.bridgeCredential};
    }
  });
}
