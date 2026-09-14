import test from 'node:test';
import assert from 'node:assert/strict';
import {issuePair,consumePair,validateBundle} from '../src/proton/extension-policy.js';
import {normalizeCookieState,cookieHeaderForUrl} from '../src/proton/cookies.js';
const fixture=()=>({version:1,source:'https://mail.proton.me',uid:'one',capturedAt:1000,email:'test@proton.me',user:{ID:'u'},keySalts:[{ID:'k',KeySalt:'fixture'}],cookies:[{name:'AUTH-one',value:'fixture',domain:'.proton.me',hostOnly:false,path:'/api/',secure:true,httpOnly:true,sameSite:'lax',session:true,expiresAt:null,expirationDate:null}]});
function storage(){const m=new Map();let queue=Promise.resolve();const s={get:async k=>m.get(k),put:async(k,v)=>m.set(k,v),delete:async k=>m.delete(k),transaction:fn=>{const result=queue.then(()=>fn(s));queue=result.catch(()=>{});return result;}};return s;}
test('one-time pair: bound identity, UID, email, expiration and concurrent replay',async()=>{
 const s=storage();const params={actorId:'owner',uid:'one',email:'test@proton.me'};
 const p=await issuePair(s,params,params.email,1000);
 assert.notEqual((await s.get('proton:extensionPair:v1')).hash,p.token);
 const input={actorId:'owner',token:p.token,bundle:fixture()};
 await assert.rejects(consumePair(s,{...input,actorId:'other'},1001));
 await assert.rejects(consumePair(s,{...input,bundle:{...fixture(),uid:'two'}},1001));
 await assert.rejects(consumePair(s,input,p.expiresAt));
 const results=await Promise.allSettled([consumePair(s,input,1001),consumePair(s,input,1001)]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
});
test('new pairing invalidates old pairing and mismatched account cannot pair',async()=>{
 const s=storage(),params={actorId:'owner',uid:'one',email:'test@proton.me'};
 const old=await issuePair(s,params,params.email,1000);await issuePair(s,params,params.email,1000);
 await assert.rejects(consumePair(s,{...params,token:old.token,bundle:fixture()},1001));
 await assert.rejects(issuePair(s,params,'wrong@proton.me',1000));
});
test('bundle rejects foreign hosts, header injection, wrong UID, partitions and stale captures',()=>{
 const b=fixture();assert.equal(validateBundle(b,b.email,1000).uid,'one');
 for(const patch of [{domain:'.evil.com'},{value:'a\r\nInjected: x'},{name:'AUTH-two'},{partitionKey:{}},{expiresAt:0}]){
  assert.throws(()=>validateBundle({...b,cookies:[{...b.cookies[0],...patch}]},b.email,1000));
 }
 assert.throws(()=>validateBundle(b,b.email,9999999));
});
test('cookie attributes retained while request path rules remain enforced',()=>{
 const b=fixture();const state=normalizeCookieState(validateBundle(b,b.email,1000).cookies,1000);
 assert.equal(state[0].httpOnly,true);assert.equal(state[0].sameSite,'lax');assert.equal(state[0].secure,true);
 assert.equal(cookieHeaderForUrl(state,'https://mail.proton.me/api/auth/refresh',1000),'AUTH-one=fixture');
 assert.equal(cookieHeaderForUrl(state,'https://mail.proton.me/',1000),'');
 assert.equal(cookieHeaderForUrl(state,'https://other.example/api/',1000),'');
});
