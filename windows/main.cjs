const {app,BrowserWindow,ipcMain,protocol,clipboard,shell,safeStorage,dialog,Tray,Menu,nativeTheme}=require('electron');
const fs=require('node:fs/promises');
const path=require('node:path');
const crypto=require('node:crypto');
const {createHost}=require('./host.cjs');
const {createBrowserBridge,protectBrowserSession,EXTENSION_ID}=require('./browser-bridge.cjs');
const ROOT=path.resolve(__dirname,'..'),ENTRY='vault://app/ui/index.html';
app.setName('private-vault');
const profileDir=app.commandLine.getSwitchValue('vault-profile-dir');
if(profileDir&&path.isAbsolute(profileDir))app.setPath('userData',path.resolve(profileDir));
let win,tray,bridge,quitting=false,rendererReady=false;
const pending=new Map();
function validSender(event){return win&&event.sender===win.webContents&&event.senderFrame===win.webContents.mainFrame&&event.senderFrame.url===ENTRY;}
function showWindow(){if(!win||win.isDestroyed())return;if(win.isMinimized())win.restore();win.show();win.focus();}
function rejectPending(){for(const item of pending.values()){clearTimeout(item.timer);item.resolve({requestId:item.request.requestId,ok:false,error:{code:'app_unavailable',message:'密码界面正在重新加载，请稍后重试。'}});}pending.clear();}
function dispatchBrowser(request){
 if(!request||typeof request.requestId!=='string'||request.requestId.length>100||typeof request.command!=='string')return Promise.resolve({requestId:null,ok:false,error:{code:'invalid_request',message:'浏览器请求格式无效。'}});
 if(!rendererReady||!win||win.isDestroyed())return Promise.resolve({requestId:request.requestId,ok:false,error:{code:'app_starting',message:'密码软件正在准备，请稍后重试。'}});
 if(pending.size>=32)return Promise.resolve({requestId:request.requestId,ok:false,error:{code:'busy',message:'请稍后再试。'}});
 const id=crypto.randomUUID();return new Promise(resolve=>{const timer=setTimeout(()=>{pending.delete(id);resolve({requestId:request.requestId,ok:false,error:{code:'request_timeout',message:'操作暂未完成，请重试。'}});},20000);pending.set(id,{resolve,timer,request});win.webContents.send('vault:browser-request',{id,request});});
}
async function start(){
 protocol.handle('vault',async request=>{
  try{const u=new URL(request.url),relative=decodeURIComponent(u.pathname).replace(/^\/+/, ''),target=path.resolve(ROOT,relative);if(u.hostname!=='app'||!/^(ui|core)\//.test(relative)||!target.startsWith(ROOT+path.sep)||relative.includes('..'))return new Response('Forbidden',{status:403});
   const data=await fs.readFile(target),mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'}[path.extname(target)]??'application/octet-stream';
   return new Response(data,{headers:{'Content-Type':mime,'Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'"}});
  }catch{return new Response('Not found',{status:404});}
 });
 const host=createHost({dataDir:app.getPath('userData'),clipboard,shell,safeStorage,dialog,getWindow:()=>win});
 const routes={'vault:config':'getConfig','vault:read':'readLocal','vault:write':'writeLocal','vault:state':'writeState','vault:import':'chooseImportFile','vault:export':'saveExportFile','vault:new':'backupAndReplace','vault:request':'request','vault:copy':'copyText','vault:external':'openExternal'};
 for(const [channel,method] of Object.entries(routes))ipcMain.handle(channel,async(event,...args)=>{if(!validSender(event))throw new Error('拒绝非应用页面访问');return host[method](...args);});
 ipcMain.handle('vault:browser-settings',event=>{if(!validSender(event))throw new Error('拒绝非应用页面访问');return bridge?.settings()??{enabled:false,connected:false,registered:false,extensionId:EXTENSION_ID};});
 ipcMain.handle('vault:browser-enable',async(event,value)=>{if(!validSender(event)||typeof value!=='boolean')throw new Error('浏览器助手设置无效');if(!bridge)throw new Error('本机浏览器连接不可用，请重启软件');return bridge.setEnabled(value);});
 ipcMain.handle('vault:extension-folder',async event=>{if(!validSender(event))throw new Error('拒绝非应用页面访问');const target=path.join(app.getPath('userData'),'browser-extension');await fs.cp(path.join(ROOT,'chrome'),target,{recursive:true,filter:source=>!source.split(path.sep).includes('tests')});const error=await shell.openPath(target);if(error)throw new Error('扩展目录无法打开');return target;});
 ipcMain.on('vault:browser-ready',event=>{if(validSender(event))rendererReady=true;});
 ipcMain.on('vault:browser-response',(event,value)=>{if(!validSender(event)||!value||typeof value.id!=='string')return;const item=pending.get(value.id);if(!item)return;pending.delete(value.id);clearTimeout(item.timer);item.resolve({requestId:item.request.requestId,...value.response});});
 win=new BrowserWindow({width:1280,height:840,minWidth:900,minHeight:620,title:'私密密码库',backgroundColor:nativeTheme.shouldUseDarkColors?'#101418':'#eef2f6',show:false,autoHideMenuBar:true,icon:path.join(__dirname,'app.ico'),webPreferences:{preload:path.join(__dirname,'preload.cjs'),contextIsolation:true,nodeIntegration:false,sandbox:true,webSecurity:true,backgroundThrottling:false}});
 win.removeMenu();try{if(process.platform==='win32')win.setBackgroundMaterial('mica');}catch{}
 win.webContents.on('will-navigate',(event,url)=>{if(url!==ENTRY)event.preventDefault();});win.webContents.setWindowOpenHandler(()=>({action:'deny'}));
 win.webContents.on('did-start-loading',()=>{rendererReady=false;rejectPending();});win.on('close',event=>{if(!quitting){event.preventDefault();win.hide();}});
 tray=new Tray(path.join(__dirname,'app.ico'));tray.setToolTip('私密密码库 · 关闭窗口后继续运行');tray.on('double-click',showWindow);tray.setContextMenu(Menu.buildFromTemplate([{label:'打开私密密码库',click:showWindow},{type:'separator'},{label:'退出',click:()=>{quitting=true;app.quit();}}]));
 const browserHost=app.isPackaged?path.join(process.resourcesPath,'browser-host.exe'):path.join(ROOT,'dist/browser-host.exe');
 try{bridge=await createBrowserBridge({dataDir:app.getPath('userData'),safeStorage,dispatch:dispatchBrowser,isPackaged:app.isPackaged,executable:browserHost,protectSession:session=>protectBrowserSession(browserHost,session),onSettings:settings=>{if(win&&!win.isDestroyed())win.webContents.send('vault:browser-settings-changed',settings);}});}catch{bridge=null;}
 nativeTheme.on('updated',()=>{if(win&&!win.isDestroyed())win.setBackgroundColor(nativeTheme.shouldUseDarkColors?'#101418':'#eef2f6');});win.once('ready-to-show',()=>win.show());await win.loadURL(ENTRY);
}
{
 protocol.registerSchemesAsPrivileged([{scheme:'vault',privileges:{standard:true,secure:true,supportFetchAPI:true,corsEnabled:true}}]);const oneInstance=app.requestSingleInstanceLock();if(!oneInstance)app.quit();app.on('second-instance',showWindow);
 app.on('before-quit',()=>{quitting=true;rendererReady=false;rejectPending();bridge?.close();tray?.destroy();});app.whenReady().then(()=>{if(oneInstance)return start();}).catch(()=>{console.error('应用启动失败，请检查本机存储权限。');quitting=true;app.quit();});app.on('window-all-closed',()=>{if(quitting)app.quit();});
}
