// Site-server adapter, not a Tesla relay HTTP authentication mechanism.
// readPlatformUser must be the official Sites getChatGPTUser server helper.
// A management account ID, email, tool arguments, or service bypass token must
// never be substituted for the Site-scoped owner ID verified during setup.
export function createSiteOwnerVerifier({readPlatformUser,expectedOwnerId}){
 const valid=typeof expectedOwnerId==='string'&&/^[a-zA-Z0-9:_-]{8,128}$/.test(expectedOwnerId);
 if(typeof readPlatformUser!=='function')throw Error('platform_identity_adapter_required');
 return async function verifyOwner(){
  if(!valid)throw Error('owner_binding_required');
  let user;try{user=await readPlatformUser()}catch{throw Error('owner_authentication_required')}
  if(!user||user.userId!==expectedOwnerId)throw Error('owner_authentication_required');
  return Object.freeze({verified:true,ownerId:expectedOwnerId});
 };
}
