import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source=readFileSync(new URL('../lib/relay.js', import.meta.url),'utf8');

test('vehicle list requires explicit Tesla location sharing permission',()=>{
  assert.match(source,/locationAllowed:v\.granular_access\?\.hide_private===false/);
  assert.match(source,/locationPrivacyVerified:v\.granular_access\?\.hide_private===false/);
  assert.doesNotMatch(source,/locationAllowed:v\.granular_access\?\.hide_private!==true/);
});

test('missing or private sharing indicators do not authorize location',()=>{
  const locationAllowed=v=>v.granular_access?.hide_private===false;
  assert.equal(locationAllowed({granular_access:{hide_private:false}}),true);
  assert.equal(locationAllowed({granular_access:{hide_private:true}}),false);
  assert.equal(locationAllowed({granular_access:{}}),false);
  assert.equal(locationAllowed({}),false);
});
