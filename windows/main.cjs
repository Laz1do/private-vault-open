const {app,BrowserWindow,ipcMain,protocol,clipboard,shell,safeStorage,dialog}=require('electron');
const fs=require('node:fs/promises');
const path=require('node:path');
const {createHost}=require('./host.cjs');
const ROOT=path.resolve(__dirname,'..');
const ENTRY='vault://app/ui/index.html';
protocol.registerSchemesAsPrivileged([{scheme:'vault',privileges:{standard:true,secure:true,supportFetchAPI:true,corsEnabled:true}}]);
app.setName('private-vault');
const oneInstance=app.requestSingleInstanceLock();if(!oneInstance)app.quit();
let win;
async function start(){
  protocol.handle('vault',async request=>{
    try{const u=new URL(request.url);const relative=decodeURIComponent(u.pathname).replace(/^\/+/, '');const target=path.resolve(ROOT,relative);if(u.hostname!=='app' || !/^(ui|core)\//.test(relative) || !target.startsWith(ROOT+path.sep) || relative.includes('..'))return new Response('Forbidden',{status:403});
      const data=await fs.readFile(target);const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'}[path.extname(target)]??'application/octet-stream';
      return new Response(data,{headers:{'Content-Type':mime,'Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"}});
    }catch{return new Response('Not found',{status:404});}
  });
  const host=createHost({dataDir:app.getPath('userData'),clipboard,shell,safeStorage,dialog,getWindow:()=>win});
  const routes={'vault:config':'getConfig','vault:read':'readLocal','vault:write':'writeLocal','vault:state':'writeState','vault:import':'chooseImportFile','vault:export':'saveExportFile','vault:request':'request','vault:copy':'copyText','vault:external':'openExternal'};
  for(const [channel,method] of Object.entries(routes))ipcMain.handle(channel,async(event,...args)=>{if(!win || event.sender!==win.webContents || event.senderFrame!==win.webContents.mainFrame || event.senderFrame.url!==ENTRY)throw new Error('拒绝非应用页面访问');return host[method](...args);});
  win=new BrowserWindow({width:1160,height:800,minWidth:720,minHeight:560,title:'私密密码库',backgroundColor:'#f5f6f3',show:false,autoHideMenuBar:true,icon:path.join(__dirname,'app.ico'),webPreferences:{preload:path.join(__dirname,'preload.cjs'),contextIsolation:true,nodeIntegration:false,sandbox:true,webSecurity:true}});
  win.removeMenu();win.webContents.on('will-navigate',(event,url)=>{if(url!==ENTRY)event.preventDefault();});win.webContents.setWindowOpenHandler(()=>({action:'deny'}));
  win.once('ready-to-show',()=>win.show());await win.loadURL(ENTRY);
}
app.on('second-instance',()=>{if(win){if(win.isMinimized())win.restore();win.focus();}});
app.whenReady().then(()=>{if(oneInstance)return start();}).catch(error=>{console.error('应用启动失败：',error.message);app.quit();});
app.on('window-all-closed',()=>app.quit());
