const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const crypto=require('node:crypto');
const net=require('node:net');
const {PassThrough}=require('node:stream');
const {once}=require('node:events');
const {createBrowserBridge,runNativeProxy,encodeMessage,createMessageDecoder,ORIGIN,EXTENSION_ID}=require('../browser-bridge.cjs');
function protectedStorage(){const key=crypto.randomBytes(32);return {
 isEncryptionAvailable:()=>true,
 encryptString(text){const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);return Buffer.concat([iv,cipher.update(text,'utf8'),cipher.final(),cipher.getAuthTag()]);},
 decryptString(bytes){const decipher=crypto.createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));decipher.setAuthTag(bytes.subarray(-16));return Buffer.concat([decipher.update(bytes.subarray(12,-16)),decipher.final()]).toString('utf8');},
};}
function inbox(stream){const messages=[],waiters=[];stream.on('data',createMessageDecoder(message=>{
 const index=waiters.findIndex(waiter=>waiter.predicate(message));if(index<0)messages.push(message);else{const [waiter]=waiters.splice(index,1);clearTimeout(waiter.timer);waiter.resolve(message);}
},error=>{for(const waiter of waiters.splice(0)){clearTimeout(waiter.timer);waiter.reject(error);}}));return {
 messages,
 next(predicate=()=>true){const index=messages.findIndex(predicate);if(index>=0)return Promise.resolve(messages.splice(index,1)[0]);return new Promise((resolve,reject)=>{const held={predicate,resolve,reject};held.timer=setTimeout(()=>{const at=waiters.indexOf(held);if(at>=0)waiters.splice(at,1);reject(new Error('fixture response timeout'));},3000);waiters.push(held);});},
};}
async function fixture(t,dispatch=async request=>({requestId:request.requestId,ok:true,result:{command:request.command}})){
 const dataDir=await fs.mkdtemp(path.join(os.tmpdir(),'private-vault-browser-bridge-test-')),safeStorage=protectedStorage(),calls=[],notices=[];
 const bridge=await createBrowserBridge({dataDir,safeStorage,onSettings:value=>notices.push(value),dispatch:async request=>{calls.push(request);return dispatch(request);}});
 t.after(async()=>{bridge.close();if(!path.resolve(dataDir).startsWith(path.resolve(os.tmpdir())+path.sep+'private-vault-browser-bridge-test-'))throw new Error('Unsafe cleanup');await fs.rm(dataDir,{recursive:true,force:true});});
 const state=JSON.parse(await fs.readFile(path.join(dataDir,'browser-session.json'),'utf8')),session=JSON.parse(safeStorage.decryptString(Buffer.from(state.secret,'base64')));
 return {dataDir,safeStorage,bridge,calls,notices,session,state};
}
async function proxy(t,f,options={}){const stdin=new PassThrough(),stdout=new PassThrough(),messages=inbox(stdout);let ended=0;
 await runNativeProxy({dataDir:f.dataDir,safeStorage:f.safeStorage,origin:ORIGIN,stdin,stdout,onEnd:()=>{ended++;},...options});
 t.after(()=>{stdin.end();stdout.end();});return {stdin,stdout,messages,ended:()=>ended,send(request){stdin.write(encodeMessage(request));}};
}
async function waitFor(predicate){for(let i=0;i<100;i++){if(predicate())return;await new Promise(resolve=>setTimeout(resolve,5));}throw new Error('fixture condition timeout');}

test('native framing decodes split UTF8 bodies and multiple coalesced messages without crossing boundaries',()=>{
 const found=[],errors=[],decode=createMessageDecoder(value=>found.push(value),error=>errors.push(error));
 const first={requestId:'first',command:'matches',params:{title:'中文 🔐'}},second={requestId:'second',command:'status'};
 const bytes=Buffer.concat([encodeMessage(first),encodeMessage(second)]);
 for(let offset=0;offset<bytes.length;offset+=3)decode(bytes.subarray(offset,offset+3));
 assert.deepEqual(found,[first,second]);assert.deepEqual(errors,[]);
 const long=encodeMessage({command:'valid',text:'x'.repeat(130000)});decode(Buffer.concat([long,long,long]));assert.equal(found.length,5);
});

test('malformed, oversized or invalid UTF8 frames stop decoding permanently and do not expose their contents in errors',()=>{
 const frame=body=>{const head=Buffer.alloc(4);head.writeUInt32LE(body.length);return Buffer.concat([head,body]);};
 const huge=Buffer.alloc(4);huge.writeUInt32LE(256*1024+1);
 for(const bad of [Buffer.alloc(4),huge,frame(Buffer.from([0xc3,0x28])),frame(Buffer.from('[]')),frame(Buffer.from('null')),frame(Buffer.from('{secret-password-invalid-json'))]){
  const found=[],errors=[],decode=createMessageDecoder(value=>found.push(value),error=>errors.push(error));decode(bad);decode(encodeMessage({command:'status'}));
  assert.equal(found.length,0);assert.equal(errors.length,1);assert.equal(errors[0].message,'浏览器通信格式无效');
 }
 assert.throws(()=>encodeMessage({text:'x'.repeat(256*1024)}),/过大/);
});

test('the saved pipe capability is protected, helpers start disabled and disabled commands never reach the vault dispatch',async t=>{
 const f=await fixture(t),raw=await fs.readFile(path.join(f.dataDir,'browser-session.json'),'utf8');
 assert.ok(!raw.includes(f.session.token));assert.ok(!raw.includes(f.session.pipeName));assert.match(f.session.token,/^[a-f0-9]{64}$/);
 assert.equal(f.bridge.settings().enabled,false);assert.equal(f.bridge.settings().extensionId,EXTENSION_ID);
 const p=await proxy(t,f);p.send({requestId:'disabled',command:'matches'});
 assert.equal((await p.messages.next()).error.code,'assistant_disabled');assert.equal(f.calls.length,0);
 p.send({requestId:'status',command:'status'});assert.equal((await p.messages.next()).ok,true);assert.equal(f.calls.length,1);
 await f.bridge.setEnabled(true);p.send({requestId:'enabled',command:'matches'});assert.equal((await p.messages.next()).ok,true);assert.equal(f.calls.length,2);
 await f.bridge.setEnabled(false);p.send({requestId:'disabled_again',command:'confirm'});assert.equal((await p.messages.next()).error.code,'assistant_disabled');assert.equal(f.calls.length,2);
 assert.ok(f.notices.some(state=>state.connected));
});

test('unknown extension origin and unavailable system protection are rejected without connecting to the app',async t=>{
 const f=await fixture(t);const wrong=await proxy(t,f,{origin:'chrome-extension://'+'a'.repeat(32)+'/'});wrong.send({requestId:'origin',command:'status'});
 assert.equal((await wrong.messages.next()).error.code,'origin_forbidden');assert.equal(f.bridge.settings().connected,false);await waitFor(()=>wrong.ended()===1);
 const unsafe=await proxy(t,f,{safeStorage:{isEncryptionAvailable:()=>false}});unsafe.send({requestId:'unsafe',command:'status'});
 assert.equal((await unsafe.messages.next()).error.code,'app_unavailable');assert.equal(f.calls.length,0);
 await waitFor(()=>unsafe.ended()===1);
});

test('unauthenticated pipe connections and incorrect capability tokens close without dispatching any command',async t=>{
 const f=await fixture(t);await f.bridge.setEnabled(true);
 for(const first of [{requestId:'not_hello',command:'matches'},{command:'hello',token:'0'.repeat(64)},{command:'hello',token:f.session.token+'x'}]){
  const socket=net.createConnection(f.session.pipeName);socket.on('error',()=>{});await once(socket,'connect');const closed=once(socket,'close');socket.write(encodeMessage(first));await closed;
 }
 assert.equal(f.calls.length,0);assert.equal(f.bridge.settings().connected,false);
});

test('proxy rejects duplicate request IDs, bounds outstanding requests and drops late replies after timeout',async t=>{
 let finish;const held=new Promise(resolve=>{finish=resolve;});
 const f=await fixture(t,async request=>{await held;return {requestId:request.requestId,ok:true,result:{saved:true}};});await f.bridge.setEnabled(true);
 const p=await proxy(t,f,{requestTimeout:500});
 p.send({requestId:'same',command:'confirm'});p.send({requestId:'same',command:'confirm'});
 assert.equal((await p.messages.next(message=>message.error?.code==='invalid_request')).requestId,'same');
 for(let i=0;i<31;i++)p.send({requestId:'pending_'+i,command:'matches'});
 p.send({requestId:'overflow',command:'matches'});assert.equal((await p.messages.next(message=>message.requestId==='overflow')).error.code,'busy');
 const timed=await p.messages.next(message=>message.requestId==='same');assert.equal(timed.error.code,'request_timeout');
 finish();await new Promise(resolve=>setTimeout(resolve,30));assert.ok(!p.messages.messages.some(message=>message.ok===true));
});

test('app closure rejects pending proxy work, ends the native process once and disallows preferences writes afterwards',async t=>{
 const f=await fixture(t,async()=>new Promise(()=>{}));await f.bridge.setEnabled(true);
 const p=await proxy(t,f);p.send({requestId:'closing',command:'fill'});await waitFor(()=>f.calls.length===1);
 const before=await fs.readFile(path.join(f.dataDir,'browser-settings.json'),'utf8');f.bridge.close();
 assert.equal((await p.messages.next()).error.code,'app_unavailable');await waitFor(()=>p.ended()===1);
 await assert.rejects(f.bridge.setEnabled(false),/关闭/);assert.equal(await fs.readFile(path.join(f.dataDir,'browser-settings.json'),'utf8'),before);
 await assert.rejects(fs.readFile(path.join(f.dataDir,'browser-session.json')),{code:'ENOENT'});
 p.stdin.end();await new Promise(resolve=>setTimeout(resolve,10));assert.equal(p.ended(),1);
});

test('application dispatch failures return a generic error without leaking credential-bearing errors',async t=>{
 const f=await fixture(t,async()=>{throw new Error('secret-password and key');});await f.bridge.setEnabled(true);const p=await proxy(t,f);
 p.send({requestId:'failure',command:'confirm'});const response=await p.messages.next();assert.equal(response.error.code,'request_failed');assert.ok(!JSON.stringify(response).includes('secret-password'));
});

test('close only removes its own session capability and preserves a newer app session',async t=>{
 const f=await fixture(t),replacement={v:1,secret:'newer-protected-fixture'};
 await fs.writeFile(path.join(f.dataDir,'browser-session.json'),JSON.stringify(replacement));f.bridge.close();
 assert.deepEqual(JSON.parse(await fs.readFile(path.join(f.dataDir,'browser-session.json'),'utf8')),replacement);
});

test('corrupt or noncanonical protected session data cannot choose a pipe endpoint',async t=>{
 const f=await fixture(t);const valid=JSON.parse(await fs.readFile(path.join(f.dataDir,'browser-session.json'),'utf8'));
 for(const state of [{v:2,secret:valid.secret},{v:1,secret:valid.secret+'\n'},{v:1,secret:f.safeStorage.encryptString(JSON.stringify({pipeName:'\\\\.\\pipe\\other-product',token:f.session.token})).toString('base64')}]){
  await fs.writeFile(path.join(f.dataDir,'browser-session.json'),JSON.stringify(state));const p=await proxy(t,f);p.send({requestId:'corrupt',command:'status'});
  assert.equal((await p.messages.next()).error.code,'app_unavailable');
 }
 assert.equal(f.calls.length,0);
});
