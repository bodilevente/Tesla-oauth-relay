import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createTeslaLinkBroker, pkceChallenge, newPkceVerifier, TeslaLinkError} from '../lib/oauth-bridge-broker.mjs';
const callback = 'https://my-private-site.example/auth/tesla/callback';
const credential = 'dummy_encrypted_bridge_credential_123456789';
const key = randomBytes(32).toString('base64url');
const state = 'site_session_oauth_state_1234567890abc';
class FakeStore {
  records = new Map();
  async put(k,record) {this.records.set(k,record)}
  async take(k) {const v=this.records.get(k);this.records.delete(k);return v ?? null}
}
const create = (store = new FakeStore(), clock = () => Date.now()) =>
  createTeslaLinkBroker({ticketStore:store,allowedSiteCallback:callback,ticketKeyBase64url:key,clock});

test('PKCE verifier and challenge are randomly formed base64url strings',()=>{
  const a=newPkceVerifier(),b=newPkceVerifier();
  assert.match(a,/^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(a,b);
  assert.match(pkceChallenge(a),/^[A-Za-z0-9_-]{43}$/);
  assert.throws(()=>pkceChallenge('x'),/invalid_pkce_verifier/);
});

test('owner-approved ticket is exchanged once using PKCE and fixed callback',async()=>{
  const store = new FakeStore(), broker = create(store), verifier = newPkceVerifier();
  const {callbackUrl} = await broker.issue({bridgeCredential:credential,
    codeChallenge:pkceChallenge(verifier),state,redirectUri:callback});
  assert.ok(callbackUrl.startsWith(callback+'?'));
  assert.ok(!callbackUrl.includes(credential));
  assert.ok(!JSON.stringify([...store.records.values()]).includes(credential));
  const url=new URL(callbackUrl);
  assert.equal(url.searchParams.get('state'),state);
  const code=url.searchParams.get('code');
  assert.match(code,/^[A-Za-z0-9_-]{43}$/);
  const first=await broker.redeem({code,codeVerifier:verifier,redirectUri:callback});
  assert.deepEqual(first,{bridgeCredential:credential});
  await assert.rejects(broker.redeem({code,codeVerifier:verifier,redirectUri:callback}),
    /authorization_code_invalid/);
});

test('wrong PKCE verifier consumes code without disclosing bridge credential',async()=>{
  const broker=create(), verifier=newPkceVerifier();
  const {callbackUrl}=await broker.issue({bridgeCredential:credential,
    codeChallenge:pkceChallenge(verifier),state,redirectUri:callback});
  const code=new URL(callbackUrl).searchParams.get('code');
  await assert.rejects(broker.redeem({code,codeVerifier:newPkceVerifier(),redirectUri:callback}),
    e=>e.code==='authorization_code_invalid' && !e.message.includes(credential));
  await assert.rejects(broker.redeem({code,codeVerifier:verifier,redirectUri:callback}),
    /authorization_code_invalid/);
});

test('tickets expire after configured short TTL even if storage has not purged',async()=>{
  let now=1000000000000; const broker=create(new FakeStore(),()=>now);
  const verifier=newPkceVerifier();
  const {callbackUrl}=await broker.issue({bridgeCredential:credential,
    codeChallenge:pkceChallenge(verifier),state,redirectUri:callback});
  const code=new URL(callbackUrl).searchParams.get('code');
  now+=91_000;
  await assert.rejects(broker.redeem({code,codeVerifier:verifier,redirectUri:callback}),
    /authorization_code_invalid/);
});

test('redirect must match a configured HTTPS Site callback exactly',async()=>{
  assert.throws(()=>createTeslaLinkBroker({ticketStore:new FakeStore(),ticketKeyBase64url:key,allowedSiteCallback:'http://insecure.example/callback'}),
    /invalid_callback_configuration/);
  const broker=create(), verifier=newPkceVerifier();
  await assert.rejects(broker.issue({bridgeCredential:credential,
    codeChallenge:pkceChallenge(verifier),state,redirectUri:'https://attacker.example/callback'}),
    /invalid_authorization_request/);
});

test('rejects arbitrary credential, state or code; returns no upstream internals',async()=>{
  const broker=create(), verifier=newPkceVerifier();
  await assert.rejects(broker.issue({bridgeCredential:'short',
    codeChallenge:pkceChallenge(verifier),state,redirectUri:callback}),
    /invalid_authorization_request/);
  await assert.rejects(broker.issue({bridgeCredential:credential,
    codeChallenge:pkceChallenge(verifier),state:'x',redirectUri:callback}),
    /invalid_authorization_request/);
  await assert.rejects(broker.redeem({code:'bad',codeVerifier:verifier,redirectUri:callback}),
    /authorization_code_invalid/);
});
