const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const {EventEmitter}=require('node:events');
const {PassThrough}=require('node:stream');
const {protectBrowserSession,createBrowserBridge,encodeMessage,createMessageDecoder}=require('../browser-bridge.cjs');
const SESSION={pipeName:'\\\\.\\pipe\\private-vault-12345678-1234-1234-1234-123456789abc',token:'a'.repeat(64)};
const SECRET=Buffer.from('fixture protected bytes').toString('base64');
function fixtureChild(reply,exit=0){let called,killed=0,input;const child=new EventEmitter();child.stdin=new PassThrough();child.stdout=new PassThrough();
 child.kill=()=>{killed++;return true;};
 child.stdin.on('data',createMessageDecoder(value=>{input=value;},()=>{}));
 const spawnProcess=(executable,args,options)=>{called={executable,args,options};setImmediate(()=>{
  if(typeof reply==='function')reply(child);else{child.stdout.write(reply);child.stdout.end();child.emit('close',exit,null);}
 });return child;};
 return {spawnProcess,child,called:()=>called,input:()=>input,killed:()=>killed};
}

test('DPAPI helper receives secrets only over hidden framed stdin and resolves one strict successful framed response',async()=>{
 const f=fixtureChild(child=>{const frame=encodeMessage({secret:SECRET});child.stdout.write(frame.subarray(0,2));child.stdout.write(frame.subarray(2,7));child.stdout.write(frame.subarray(7));child.stdout.end();child.emit('close',0,null);});
 assert.equal(await protectBrowserSession('C:\\fixture\\BrowserHost.exe',SESSION,{spawnProcess:f.spawnProcess}),SECRET);
 assert.deepEqual(f.input(),SESSION);assert.deepEqual(f.called().args,['--protect-session']);assert.equal(f.called().options.windowsHide,true);assert.deepEqual(f.called().options.stdio,['pipe','pipe','ignore']);
 assert.ok(!JSON.stringify(f.called()).includes(SESSION.token));assert.equal(f.killed(),0);
});

test('DPAPI helper rejects bad exit status, truncation, extra frames, invalid UTF8 and loose secret schemas',async()=>{
 const head=Buffer.alloc(4);head.writeUInt32LE(2);
 const good=encodeMessage({secret:SECRET});
 const cases=[
  [good,1],[good.subarray(0,-1),0],[Buffer.concat([good,good]),0],
  [Buffer.concat([head,Buffer.from([0xc3,0x28])]),0],[encodeMessage({secret:SECRET,token:SESSION.token}),0],
  [encodeMessage({secret:''}),0],[encodeMessage({secret:SECRET+'\n'}),0],[encodeMessage({secret:'AA==junk'}),0],
  [encodeMessage({secret:'A'.repeat(32772)}),0],[Buffer.from('secret token logged before frame'),0],
 ];
 for(const [reply,exit] of cases){const f=fixtureChild(reply,exit);await assert.rejects(protectBrowserSession('fixture.exe',SESSION,{spawnProcess:f.spawnProcess}),error=>error.message==='浏览器连接密钥保护失败，请重新打开软件。');assert.equal(f.killed(),1);}
});

test('DPAPI helper timeout kills the process and does not leak its output or accept a late reply',async()=>{
 const f=fixtureChild(()=>{});
 await assert.rejects(protectBrowserSession('fixture.exe',SESSION,{spawnProcess:f.spawnProcess,timeout:15}),/保护失败/);assert.equal(f.killed(),1);
 assert.equal(f.child.stdin.destroyed,true);assert.equal(f.child.stdout.destroyed,true);
 f.child.emit('close',0,null);assert.equal(f.killed(),1);
});

test('helper launch errors remain generic and invalid capability requests never launch a process',async()=>{
 let launches=0;const spawnProcess=()=>{launches++;throw new Error(SESSION.token);};
 await assert.rejects(protectBrowserSession('fixture.exe',SESSION,{spawnProcess}),error=>!error.message.includes(SESSION.token)&&/保护失败/.test(error.message));assert.equal(launches,1);
 for(const invalid of [{...SESSION,token:'short'},{...SESSION,pipeName:'\\\\.\\pipe\\other-product'},{...SESSION,extra:true},null])await assert.rejects(protectBrowserSession('fixture.exe',invalid,{spawnProcess}),/请求无效/);
 assert.equal(launches,1);
});

test('bridge can use a dedicated protection callback without safeStorage and stores only its protected result',async t=>{
 const dataDir=await fs.mkdtemp(path.join(os.tmpdir(),'private-vault-browser-protect-test-'));let seen;
 const bridge=await createBrowserBridge({dataDir,dispatch:async()=>{},protectSession:async session=>{seen=session;return SECRET;}});
 t.after(async()=>{bridge.close();if(!path.resolve(dataDir).startsWith(path.resolve(os.tmpdir())+path.sep+'private-vault-browser-protect-test-'))throw new Error('Unsafe cleanup');await fs.rm(dataDir,{recursive:true,force:true});});
 assert.match(seen.pipeName,/private-vault-[a-f0-9-]{36}$/);assert.match(seen.token,/^[a-f0-9]{64}$/);
 const raw=await fs.readFile(path.join(dataDir,'browser-session.json'),'utf8');assert.deepEqual(JSON.parse(raw),{v:1,secret:SECRET});assert.ok(!raw.includes(seen.token));assert.ok(!raw.includes(seen.pipeName));
});

test('bridge rejects failed or noncanonical protection before opening or publishing any session file',async t=>{
 const dataDir=await fs.mkdtemp(path.join(os.tmpdir(),'private-vault-browser-protect-test-'));
 t.after(async()=>{if(!path.resolve(dataDir).startsWith(path.resolve(os.tmpdir())+path.sep+'private-vault-browser-protect-test-'))throw new Error('Unsafe cleanup');await fs.rm(dataDir,{recursive:true,force:true});});
 for(const callback of [async()=>'',async()=>SECRET+'\n',async()=>{throw new Error('fixture helper failure');}]){
  await assert.rejects(createBrowserBridge({dataDir,dispatch:async()=>{},protectSession:callback}));assert.deepEqual(await fs.readdir(dataDir),[]);
 }
 await assert.rejects(createBrowserBridge({dataDir,dispatch:async()=>{},protectSession:true}),/配置无效/);
});
