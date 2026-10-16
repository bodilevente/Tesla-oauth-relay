import test from 'node:test';
import assert from 'node:assert/strict';
import {createRelaySiteLinkFlow,READ_SCOPES} from '../lib/site-link-flow.mjs';
const state='s'.repeat(43),challenge='c'.repeat(43);
function setup(){
 const store=new Map();let issued=0,exchanged=0,redeemed=0;
 let granted=READ_SCOPES;
 const flow=createRelaySiteLinkFlow({
  clientId:'test-client',relayCallback:'https://preview.example/api/site-callback',siteCallback:'https://private.example/auth/tesla/callback',
  pendingStore:{async put(k,v){assert.ok(!store.has(k));store.set(k,v)},async take(k){const v=store.get(k);store.delete(k);return v}},
  // Test-only identity/encryption adapters; never used by runtime.
  verifyOwnerSession:async r=>r?.owner?{verified:true,id:r.owner}:null,
  verifySiteClient:async r=>r?.server===true,
  sealPending:async p=>JSON.stringify(p),openPending:async p=>JSON.parse(p),
  exchangeTeslaCode:async p=>{exchanged++;assert.equal(p.redirectUri,'https://preview.example/api/site-callback');return {access_token:'test-access',refresh_token:'test-refresh',expires_in:3600,scope:granted}},
  sealBridge:async()=> 'z'.repeat(64),
  broker:{async issue(){issued++;return {callbackUrl:'https://private.example/auth/tesla/callback?code=test'}},async redeem(){redeemed++;return {bridgeCredential:'test-server-only'}}}
 });
 return {flow,setScopes:s=>granted=s,counts:()=>({issued,exchanged,redeemed})};
}
const begin=flow=>flow.begin({request:{owner:'owner'},siteState:state,siteChallenge:challenge,redirectUri:'https://private.example/auth/tesla/callback'});
test('consent URL restricted to official Tesla and read scopes; PKCE is enforced by the Site broker',async()=>{
 const {flow}=setup(),url=new URL((await begin(flow)).authorizationUrl);
 assert.equal(url.origin,'https://auth.tesla.com');assert.equal(url.searchParams.get('scope'),READ_SCOPES);assert.equal(url.searchParams.get('code_challenge_method'),null);
 assert.ok(!url.href.includes('verifier'));assert.ok(!url.href.includes('credential'));
});
test('callback consumes state once before token exchange',async()=>{
 const {flow,counts}=setup(),s=new URL((await begin(flow)).authorizationUrl).searchParams.get('state');
 await flow.finish({request:{owner:'owner'},state:s,code:'test-code-123456'});
 await assert.rejects(flow.finish({request:{owner:'owner'},state:s,code:'test-code-123456'}),/authorization_failed/);
 assert.deepEqual(counts(),{issued:1,exchanged:1,redeemed:0});
});
test('wrong owner and declined consent cannot issue a Site credential',async()=>{
 for(const input of [{request:{owner:'other'}},{request:{owner:'owner'},error:'access_denied'}]){
  const {flow,counts}=setup(),s=new URL((await begin(flow)).authorizationUrl).searchParams.get('state');
  await assert.rejects(flow.finish({code:'test-code-123456',state:s,...input}),/authorization_failed/);
  assert.equal(counts().exchanged,0);assert.equal(counts().issued,0);
 }
});
test('command scopes or missing scope proof fail closed',async()=>{
 for(const scope of [READ_SCOPES+' vehicle_cmds',undefined]){
  const {flow,setScopes,counts}=setup();setScopes(scope);const s=new URL((await begin(flow)).authorizationUrl).searchParams.get('state');
  await assert.rejects(flow.finish({request:{owner:'owner'},state:s,code:'test-code-123456'}),/authorization_failed/);
  assert.equal(counts().issued,0);
 }
});
test('untrusted server and callback substitution rejected',async()=>{
 const {flow,counts}=setup();
 await assert.rejects(flow.redeem({request:{},code:state,codeVerifier:challenge,redirectUri:'https://private.example/auth/tesla/callback'}),/authorization_failed/);
 await assert.rejects(flow.redeem({request:{server:true},code:state,codeVerifier:challenge,redirectUri:'https://evil.example/callback'}),/authorization_failed/);
 assert.equal(counts().redeemed,0);
});
test('start rejects unauthenticated owner and arbitrary callback',async()=>{
 const {flow}=setup();
 await assert.rejects(flow.begin({request:{},siteState:state,siteChallenge:challenge,redirectUri:'https://private.example/auth/tesla/callback'}),/authorization_failed/);
 await assert.rejects(flow.begin({request:{owner:'owner'},siteState:state,siteChallenge:challenge,redirectUri:'https://evil.example/callback'}),/authorization_failed/);
});
