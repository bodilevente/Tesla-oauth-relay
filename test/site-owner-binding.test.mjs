import test from 'node:test';
import assert from 'node:assert/strict';
import {createSiteOwnerVerifier} from '../lib/site-owner-binding.mjs';
const id='site_specific_owner_123';
test('only platform-resolved pinned identity verifies',async()=>{
 const verify=createSiteOwnerVerifier({readPlatformUser:async()=>({userId:id}),expectedOwnerId:id});
 assert.deepEqual(await verify(),{verified:true,ownerId:id});
});
test('no first-user enrollment, email fallback or request identity override',async()=>{
 for(const configuration of [
  {readPlatformUser:async()=>({userId:id})},
  {readPlatformUser:async()=>({userId:'other_visitor',email:'owner@example.test'}),expectedOwnerId:id},
  {readPlatformUser:async()=>null,expectedOwnerId:id}
 ]){
  await assert.rejects(createSiteOwnerVerifier(configuration)({userId:id,verified:true}),/owner_/);
 }
});
test('platform errors never disclose auth internals',async()=>{
 const verify=createSiteOwnerVerifier({readPlatformUser:async()=>{throw Error('private cookie details')},expectedOwnerId:id});
 await assert.rejects(verify(),e=>e.message==='owner_authentication_required');
});
