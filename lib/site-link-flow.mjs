import {randomBytes,createHash} from 'node:crypto';
export const READ_SCOPES='openid offline_access vehicle_device_data vehicle_location';
const fail=()=>{throw Error('site_link_authorization_failed')};
const hash=x=>createHash('sha256').update(x,'ascii').digest('hex');
const token=x=>typeof x==='string'&&/^[A-Za-z0-9_-]{43}$/.test(x);
function https(value){
 const u=new URL(value);
 if(u.protocol!=='https:'||u.username||u.password||u.hash||u.search||u.port)fail();
 return u;
}
// Server-only composition for the existing relay. Dependencies must be real,
// reviewed runtime adapters. Never expose the factory or credentials to MCP.
export function createRelaySiteLinkFlow({
 clientId,relayCallback,siteCallback,pendingStore,broker,
 verifyOwnerSession,verifySiteClient,sealPending,openPending,
 exchangeTeslaCode,sealBridge,clock=()=>Date.now()
}){
 const relay=https(relayCallback),site=https(siteCallback);
 if(!clientId||site.origin===relay.origin||!pendingStore?.put||!pendingStore?.take||
    !broker?.issue||!broker?.redeem||
    [verifyOwnerSession,verifySiteClient,sealPending,openPending,exchangeTeslaCode,sealBridge].some(f=>typeof f!=='function'))fail();
 const identity=async request=>{
  const owner=await verifyOwnerSession(request);
  if(!owner||owner.verified!==true||typeof owner.id!=='string'||!owner.id)fail();
  return owner.id;
 };
 return Object.freeze({
  async begin({request,siteState,siteChallenge,redirectUri}){
   try{
    const owner=await identity(request);
    if(!token(siteState)||!token(siteChallenge)||redirectUri!==site.href)fail();
    const state=randomBytes(32).toString('base64url');
    const envelope=await sealPending({owner,siteState,siteChallenge,expiresAt:clock()+180000});
    await pendingStore.put(hash(state),{sealed:envelope},180);
    const url=new URL('https://auth.tesla.com/oauth2/v3/authorize');
    url.search=new URLSearchParams({client_id:clientId,redirect_uri:relay.href,response_type:'code',
     scope:READ_SCOPES,state,
     locale:'hu-HU',prompt_missing_scopes:'true',require_requested_scopes:'true'}).toString();
    return {authorizationUrl:url.href};
   }catch{fail()}
  },
  async finish({request,state,code,error}){
   try{
    const owner=await identity(request);
    if(!token(state))fail();
    const envelope=await pendingStore.take(hash(state));
    const pending=envelope?await openPending(envelope.sealed):null;
    if(!pending||pending.owner!==owner||!Number.isFinite(pending.expiresAt)||pending.expiresAt<=clock()||
       error||typeof code!=='string'||code.length<10||code.length>4096)fail();
    // Exactly one exchange after atomic consumption; no retry on uncertain results.
    const tokens=await exchangeTeslaCode({code,redirectUri:relay.href});
    if(!tokens||typeof tokens.access_token!=='string'||typeof tokens.refresh_token!=='string'||
       !Number.isFinite(Number(tokens.expires_in))||Number(tokens.expires_in)<=0)fail();
    if(typeof tokens.scope!=='string')fail();
    const granted=new Set(tokens.scope.split(/\s+/).filter(Boolean));
    const allowed=new Set(READ_SCOPES.split(' '));
    if([...granted].some(s=>!allowed.has(s))||!granted.has('vehicle_device_data'))fail();
    const bridgeCredential=await sealBridge(tokens);
    return await broker.issue({bridgeCredential,codeChallenge:pending.siteChallenge,state:pending.siteState,redirectUri:site.href});
   }catch{fail()}
  },
  async redeem({request,code,codeVerifier,redirectUri}){
   try{
    if(await verifySiteClient(request)!==true||redirectUri!==site.href)fail();
    return await broker.redeem({code,codeVerifier,redirectUri:site.href});
   }catch{fail()}
  }
 });
}
