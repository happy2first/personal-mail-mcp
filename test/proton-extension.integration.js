import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
import {decryptJson} from '../src/proton/session-crypto.js';
class FakeSession {
 constructor(){this.env={PROTON_SESSION_KEY:'test-only-key'};this.data=new Map([['proton:session:v2',{original:true}]]);
  const data=this.data;const storage={get:async k=>data.get(k),put:async(k,v)=>data.set(k,v),delete:async k=>data.delete(k),transaction:async fn=>{
   const copy=new Map(data);try{return await fn(storage)}catch(e){data.clear();for(const [k,v] of copy)data.set(k,v);throw e;}
  }};
  this.state={storage,blockConcurrencyWhile:fn=>fn()};
 }
 getClient(){return {cfg:{id:'test',email:'test@proton.me'}}}
 async fetch(){return new Response('legacy')}
}
let mismatch=false;
class FakeClient {
 constructor(cfg){this.cfg=cfg;this.baseUrl='https://mail.proton.me/api'}
 setAuth(auth){this.auth=auth}setCookieState(c){this.cookies=c}getCookieState(){return this.cookies}
 async raw(path){return path.endsWith('/users') ? {User:{ID:'u',Keys:[{ID:'k',Active:1}]}} : {Addresses:[{Email:mismatch?'wrong@proton.me':'test@proton.me'}]}}
}
mock.module('../src/proton/key-material-session.js',{namedExports:{}});
mock.module('../src/proton/session.js',{namedExports:{ProtonSession:FakeSession}});
mock.module('../src/proton/client-v2.js',{namedExports:{ProtonClient:FakeClient}});
await import('../src/proton/extension-session.js');
const bundle=()=>({version:1,source:'https://mail.proton.me',uid:'one',capturedAt:Date.now(),email:'test@proton.me',user:{ID:'u'},keySalts:[{ID:'k',KeySalt:'fixture-salt'}],cookies:[{name:'AUTH-one',value:'fixture-cookie',domain:'mail.proton.me',hostOnly:true,path:'/api/',secure:true,httpOnly:true,expiresAt:null}]});
const call=async(s,action,payload)=>s.fetch(new Request('https://internal/action',{method:'POST',body:JSON.stringify({account:'test',action,payload})}));
async function pair(s){const r=await call(s,'extensionPair',{actorId:'owner',uid:'one',email:'test@proton.me'});return (await r.json()).data.token;}
test('successful import persists encrypted envelopes using existing AAD',async()=>{
 const s=new FakeSession();const token=await pair(s);
 const r=await call(s,'extensionImport',{actorId:'owner',token,bundle:bundle()});
 assert.equal(r.status,200);
 const auth=await decryptJson(s.data.get('proton:session:v2'),s.env.PROTON_SESSION_KEY,'test:proton:session:v2');
 assert.equal(auth.UID,'one');assert.equal(auth.KeySalts[0].KeySalt,'fixture-salt');
 assert.equal(JSON.stringify([...s.data]).includes('fixture-cookie'),false);
 assert.equal(JSON.stringify([...s.data]).includes('fixture-salt'),false);
 const again=await call(s,'extensionImport',{actorId:'owner',token,bundle:bundle()});assert.equal(again.status,400);
});
test('upstream mismatch leaves previous session intact, consumes token and hides diagnostics',async()=>{
 const s=new FakeSession();const token=await pair(s);mismatch=true;
 try {
  const r=await call(s,'extensionImport',{actorId:'owner',token,bundle:bundle()});assert.equal(r.status,400);
  assert.deepEqual(s.data.get('proton:session:v2'),{original:true});assert.equal(s.data.has('proton:extensionPair:v1'),false);
  assert.deepEqual(await r.json(),{ok:false,error:'extension_import_rejected'});
 } finally {mismatch=false;}
});
test('encryption is mandatory and unrelated actions retain legacy handling',async()=>{
 const s=new FakeSession();s.env={};
 assert.equal((await call(s,'extensionPair',{actorId:'owner',uid:'one',email:'test@proton.me'})).status,400);
 assert.equal(await (await call(s,'status',{})).text(),'legacy');
});
