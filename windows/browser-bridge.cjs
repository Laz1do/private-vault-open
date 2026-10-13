const fs=require('node:fs/promises');
const fsSync=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const net=require('node:net');
const {execFile,spawn}=require('node:child_process');
const EXTENSION_ID='dinagdpfpgbcfepiaabjccimnppakedl';
const ORIGIN=`chrome-extension://${EXTENSION_ID}/`;
const HOST_NAME='com.local.privatevault';
const LIMIT=256*1024;
const validRequest=request=>typeof request?.requestId==='string'&&/^[A-Za-z0-9_-]{1,100}$/.test(request.requestId)&&typeof request.command==='string'&&request.command.length>0&&request.command.length<=32;
const unavailable=(request,code='app_unavailable',message='请打开密码软件，并启用浏览器助手。')=>({requestId:request?.requestId??null,ok:false,error:{code,message}});
function encodeMessage(value){const body=Buffer.from(JSON.stringify(value),'utf8');if(!body.length||body.length>LIMIT)throw new Error('浏览器消息过大');const head=Buffer.alloc(4);head.writeUInt32LE(body.length);return Buffer.concat([head,body]);}
function createMessageDecoder(onMessage,onError){let buffer=Buffer.alloc(0),failed=false;return bytes=>{if(failed)return;try{buffer=Buffer.concat([buffer,bytes]);while(buffer.length>=4){const length=buffer.readUInt32LE(0);if(!length||length>LIMIT)throw new Error('浏览器消息长度无效');if(buffer.length<length+4)break;const text=new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(4,4+length));buffer=buffer.subarray(4+length);const value=JSON.parse(text);if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('浏览器消息格式无效');onMessage(value);}if(buffer.length>LIMIT+4)throw new Error('浏览器消息过大');}catch{failed=true;buffer=Buffer.alloc(0);onError(new Error('浏览器通信格式无效'));}};}
async function atomicJSON(file,value){const temp=file+'.'+crypto.randomUUID()+'.tmp';try{await fs.writeFile(temp,JSON.stringify(value),{mode:0o600,flag:'wx'});await fs.rename(temp,file);}finally{await fs.unlink(temp).catch(()=>{});}}
function protectedStorage(safeStorage){if(!safeStorage?.isEncryptionAvailable?.()||safeStorage.getSelectedStorageBackend?.()==='basic_text')throw new Error('系统密钥保护不可用');}
function checkedProtectedSession(secret){if(typeof secret!=='string'||!secret.length||secret.length>32768||secret.length%4!==0||!/^[A-Za-z0-9+/]*={0,2}$/.test(secret)||Buffer.from(secret,'base64').toString('base64')!==secret)throw new Error('浏览器连接密钥保护结果无效');return secret;}
function protectBrowserSession(executable,session,{spawnProcess=spawn,timeout=4000}={}){
 if(typeof executable!=='string'||!executable.length||!session||typeof session!=='object'||Array.isArray(session)||Object.keys(session).length!==2
  ||typeof session.pipeName!=='string'||!/^\\\\\.\\pipe\\private-vault-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(session.pipeName)
  ||typeof session.token!=='string'||!/^[a-f0-9]{64}$/.test(session.token))return Promise.reject(new Error('浏览器连接密钥保护请求无效'));
 return new Promise((resolve,reject)=>{
  let child,timer,input,settled=false,output=Buffer.alloc(0);const outputLimit=32768+256;
  const finish=(error,secret)=>{if(settled)return;settled=true;clearTimeout(timer);if(error){input?.fill(0);try{child?.kill();child?.stdin?.destroy();child?.stdout?.destroy();}catch{}reject(new Error('浏览器连接密钥保护失败，请重新打开软件。'));}else resolve(secret);};
  try{
   child=spawnProcess(executable,['--protect-session'],{windowsHide:true,stdio:['pipe','pipe','ignore']});
   timer=setTimeout(()=>finish(true),timeout);
   child.on('error',()=>finish(true));child.stdin.on('error',()=>finish(true));
   child.stdout.on('error',()=>finish(true));
   child.stdout.on('data',bytes=>{
    if(settled)return;
    if(output.length+bytes.length>outputLimit+4){finish(true);return;}output=Buffer.concat([output,bytes]);
    if(output.length>=4){const length=output.readUInt32LE(0);if(!length||length>outputLimit||output.length>length+4)finish(true);}
   });
   child.on('close',(code,signal)=>{
    if(settled)return;
    try{
     if(code!==0||signal||output.length<4||output.length!==output.readUInt32LE(0)+4)throw new Error();
     const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(output.subarray(4)));
     if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==1||!Object.hasOwn(value,'secret'))throw new Error();
     finish(false,checkedProtectedSession(value.secret));
    }catch{finish(true);}
   });
   input=encodeMessage({pipeName:session.pipeName,token:session.token});
   child.stdin.end(input,()=>input.fill(0));
  }catch{finish(true);}
 });
}
async function createBrowserBridge({dataDir,safeStorage,dispatch,isPackaged=false,executable=process.execPath,onSettings=()=>{},protectSession}){
 if(protectSession!==undefined&&typeof protectSession!=='function')throw new Error('浏览器连接保护配置无效');
 if(!protectSession)protectedStorage(safeStorage);await fs.mkdir(dataDir,{recursive:true});
 const prefsFile=path.join(dataDir,'browser-settings.json'),sessionFile=path.join(dataDir,'browser-session.json'),manifestFile=path.join(dataDir,'native-host.json');
 let enabled=false,registered=false,connections=0,closed=false,prefQueue=Promise.resolve();
 try{const prefs=JSON.parse(await fs.readFile(prefsFile,'utf8'));if(prefs.v!==1||typeof prefs.enabled!=='boolean')throw new Error();enabled=prefs.enabled;}catch(error){if(error.code!=='ENOENT')enabled=false;}
 const pipeName=`\\\\.\\pipe\\private-vault-${crypto.randomUUID()}`,token=crypto.randomBytes(32).toString('hex');
 const secret=checkedProtectedSession(protectSession?await protectSession({pipeName,token}):safeStorage.encryptString(JSON.stringify({pipeName,token})).toString('base64'));
 const sockets=new Set();
 const settings=()=>({enabled,connected:connections>0,registered,extensionId:EXTENSION_ID});
 const notify=()=>{try{onSettings(settings());}catch{}};
 const server=net.createServer(socket=>{
  sockets.add(socket);let authenticated=false,queue=Promise.resolve(),count=0;
  const timeout=setTimeout(()=>{if(!authenticated)socket.destroy();},5000);timeout.unref();
  socket.on('error',()=>{});socket.on('close',()=>{clearTimeout(timeout);sockets.delete(socket);if(authenticated){connections--;notify();}});
  socket.on('data',createMessageDecoder(message=>{
   if(!authenticated){const given=typeof message.token==='string'?Buffer.from(message.token):Buffer.alloc(0),expected=Buffer.from(token);if(message.command!=='hello'||given.length!==expected.length||!crypto.timingSafeEqual(given,expected)){socket.destroy();return;}authenticated=true;connections++;notify();clearTimeout(timeout);return;}
   if(!validRequest(message)){try{socket.write(encodeMessage(unavailable({requestId:null},'invalid_request','浏览器请求格式无效。')));}catch{socket.destroy();}return;}
   if(++count>32){socket.destroy();return;}
   queue=queue.then(async()=>{
    let response;
    if(closed)response=unavailable(message);
    else if(!enabled&&message.command!=='status')response=unavailable(message,'assistant_disabled','浏览器助手已关闭，请在软件中开启。');
    else {try{response=await dispatch(message);}catch{response=unavailable(message,'request_failed','浏览器操作未完成，请重试。');}}
    if(!socket.destroyed){try{socket.write(encodeMessage(response));}catch{socket.destroy();}}
   }).catch(()=>socket.destroy()).finally(()=>{count--;});
  },()=>socket.destroy()));
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(pipeName,()=>{server.removeListener('error',reject);resolve();});});
 server.on('error',()=>{for(const socket of sockets)socket.destroy();});
 try{await atomicJSON(sessionFile,{v:1,secret});}catch(error){await new Promise(resolve=>server.close(resolve));throw error;}
 if(isPackaged&&process.platform==='win32'){
  try{
   await atomicJSON(manifestFile,{name:HOST_NAME,description:'Private Vault browser assistant',path:executable,type:'stdio',allowed_origins:[ORIGIN]});
   for(const view of ['32','64'])await new Promise((resolve,reject)=>execFile('reg.exe',['add',`HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}`,'/ve','/t','REG_SZ','/d',manifestFile,'/f','/reg:'+view],{windowsHide:true},error=>error?reject(error):resolve()));
   registered=true;
  }catch{registered=false;}
 }
 return {settings,
  setEnabled(value){if(closed)return Promise.reject(new Error('浏览器连接已关闭'));if(typeof value!=='boolean')return Promise.reject(new Error('浏览器助手开关无效'));const job=prefQueue.then(async()=>{if(closed)throw new Error('浏览器连接已关闭');await atomicJSON(prefsFile,{v:1,enabled:value});if(closed)throw new Error('浏览器连接已关闭');enabled=value;notify();return settings();});prefQueue=job.catch(()=>{});return job;},
  close(){closed=true;for(const socket of sockets)socket.destroy();server.close();try{const current=JSON.parse(fsSync.readFileSync(sessionFile,'utf8'));if(current.secret===secret)fsSync.unlinkSync(sessionFile);}catch{}},
 };
}
async function runNativeProxy({dataDir,safeStorage,origin,stdin=process.stdin,stdout=process.stdout,onEnd=()=>{},requestTimeout=12000}){
 let socket=null,failure=null,ended=false;const pending=new Map();
 const end=()=>{if(ended)return;ended=true;for(const held of pending.values())clearTimeout(held.timer);pending.clear();socket?.destroy();try{stdout.write(Buffer.alloc(0),()=>onEnd());}catch{onEnd();}};
 const write=response=>{try{stdout.write(encodeMessage(response));}catch{end();}};
 if(origin!==ORIGIN)failure=['origin_forbidden','此扩展未获准连接密码软件。'];
 else try{
  protectedStorage(safeStorage);const state=JSON.parse(await fs.readFile(path.join(dataDir,'browser-session.json'),'utf8'));
  if(state.v!==1||typeof state.secret!=='string'||state.secret.length>32768)throw new Error();
  const bytes=Buffer.from(state.secret,'base64');if(!bytes.length||bytes.toString('base64')!==state.secret)throw new Error();
  const session=JSON.parse(safeStorage.decryptString(bytes));
  if(typeof session.pipeName!=='string'||!session.pipeName.startsWith('\\\\.\\pipe\\private-vault-')||! /^[a-f0-9]{64}$/.test(session.token))throw new Error();
  socket=net.createConnection(session.pipeName);
  await new Promise((resolve,reject)=>{const timeout=setTimeout(()=>{socket.destroy();reject(new Error());},4000);socket.once('error',error=>{clearTimeout(timeout);reject(error);});socket.once('connect',()=>{clearTimeout(timeout);resolve();});});
  socket.write(encodeMessage({command:'hello',token:session.token}));
  socket.on('data',createMessageDecoder(response=>{const held=pending.get(response.requestId);if(!held)return;clearTimeout(held.timer);pending.delete(response.requestId);write(response);},()=>socket.destroy()));
  socket.on('error',()=>{});socket.on('close',()=>{failure=['app_unavailable','密码软件已退出，请重新打开。'];for(const held of pending.values()){clearTimeout(held.timer);write(unavailable(held.request,...failure));}pending.clear();end();});
 }catch{failure=['app_unavailable','请打开密码软件，并启用浏览器助手。'];socket?.destroy();socket=null;}
 stdin.on('data',createMessageDecoder(request=>{
  if(ended)return;
  if(!validRequest(request)||pending.has(request.requestId)){write(unavailable(request,'invalid_request','浏览器请求标识或格式无效。'));return;}
  if(failure){write(unavailable(request,...failure));end();return;}
  if(pending.size>=32){write(unavailable(request,'busy','浏览器操作过多，请稍后再试。'));return;}
  const timer=setTimeout(()=>{const held=pending.get(request.requestId);if(!held)return;pending.delete(request.requestId);write(unavailable(request,'request_timeout','密码软件响应超时，请重新核对后重试。'));},requestTimeout);timer.unref?.();
  pending.set(request.requestId,{request,timer});
  try{socket.write(encodeMessage(request));}catch{clearTimeout(timer);pending.delete(request.requestId);write(unavailable(request));}
 },end));
 stdin.on('end',end);stdin.resume();
}
module.exports={EXTENSION_ID,ORIGIN,HOST_NAME,encodeMessage,createMessageDecoder,createBrowserBridge,runNativeProxy,protectBrowserSession};
