import test from 'node:test';
import assert from 'node:assert/strict';
import {handle,seal,unseal} from '../lib/relay.js';
process.env.TESLA_CLIENT_ID='test-client';process.env.TESLA_CLIENT_SECRET='test-secret-only';process.env.TESLA_SETUP_KEY='test-only-protection-key-at-least-32-characters';
const host='tesla-oauth-relay.vercel.app',origin='https://'+host;
const res=()=>({headers:{},setHeader(k,v){this.headers[k]=v;},getHeader(k){return this.headers[k];},end(v){this.body=v;}});
const bundle=()=>seal('bridge',{access:{token:'private-access',expires:Date.now()+3600000},refresh:'private-refresh',deadline:Date.now()+86400000},86400);
test('bridge is authenticated, purpose-bound, read-only and rejects foreign origins',async()=>{
 for(const body of [{action:'vehicles'},{action:'vehicles',credential:seal('admin',true,100)},{action:'wake_up',credential:bundle()}]){const r=res();await handle('bridge',{method:'POST',headers:{host},body},r);assert.ok(r.statusCode>=400);}
 const r=res();await handle('bridge',{method:'POST',headers:{host,origin:'https://evil.example'},body:{action:'vehicles',credential:bundle()}},r);assert.equal(r.statusCode,403);
});
test('native bridge reads without browser cookies and never returns Tesla tokens',async()=>{
 const old=global.fetch;global.fetch=async(url,o)=>{assert.equal(o.headers.Authorization,'Bearer private-access');return {ok:true,json:async()=>({response:[{vin:'LRWYGCEK1NC000000',display_name:'Test',state:'online'}]})};};
 try{const r=res();await handle('bridge',{method:'POST',headers:{host},body:{action:'vehicles',credential:bundle()}},r);assert.equal(r.statusCode,200);const j=JSON.parse(r.body);assert.equal(j.result.vehicles.length,1);assert.equal(r.headers['Set-Cookie'],undefined);assert.ok(!r.body.includes('private-access'));assert.ok(!r.body.includes('private-refresh'));assert.ok(unseal('bridge',j.credential));}finally{global.fetch=old;}
});
test('bridge rotates refresh credentials even if the data request fails',async()=>{
 const old=global.fetch;global.fetch=async(url)=>url.endsWith('/token')?{ok:true,json:async()=>({access_token:'new-access',refresh_token:'rotated-refresh',expires_in:3600})}:{ok:false,status:503,json:async()=>({error:'temporary'})};
 try{const b=seal('bridge',{access:{token:'expired',expires:0},refresh:'old-refresh',deadline:Date.now()+86400000},86400);const r=res();await handle('bridge',{method:'POST',headers:{host},body:{action:'vehicles',credential:b}},r);assert.equal(r.statusCode,502);const j=JSON.parse(r.body);assert.equal(unseal('bridge',j.credential).refresh,'rotated-refresh');assert.ok(!r.body.includes('new-access'));assert.ok(!r.body.includes('rotated-refresh'));}finally{global.fetch=old;}
});
test('bridge OAuth callback exports only encrypted credential, not browser Tesla cookies',async()=>{
 const old=global.fetch;global.fetch=async()=>({ok:true,json:async()=>({access_token:'private-access',refresh_token:'private-refresh',expires_in:3600})});
 try{const r=res();await handle('callback',{method:'GET',url:'/api/callback?state=expected&code=code',headers:{host,cookie:`__Host-admin=${seal('admin',true,100)}; __Host-oauth=${seal('oauth',{state:'expected',bridge:true},100)}`}},r);assert.equal(r.statusCode,200);assert.ok(r.headers['Content-Disposition'].includes('attachment'));assert.ok(!r.body.includes('private-access'));assert.ok(!r.body.includes('private-refresh'));assert.equal(r.headers['Set-Cookie'].length,1);assert.ok(unseal('bridge',JSON.parse(r.body).credential));}finally{global.fetch=old;}
});
