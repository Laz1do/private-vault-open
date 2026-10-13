const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('VaultHost',{
 getConfig:()=>ipcRenderer.invoke('vault:config'),readLocal:()=>ipcRenderer.invoke('vault:read'),writeLocal:value=>ipcRenderer.invoke('vault:write',value),writeState:(config,value)=>ipcRenderer.invoke('vault:state',config,value),
 chooseImportFile:()=>ipcRenderer.invoke('vault:import'),saveExportFile:text=>ipcRenderer.invoke('vault:export',text),backupAndReplace:(text,config,value)=>ipcRenderer.invoke('vault:new',text,config,value),
 request:(method,path,body)=>ipcRenderer.invoke('vault:request',method,path,body),copyText:text=>ipcRenderer.invoke('vault:copy',text),openExternal:url=>ipcRenderer.invoke('vault:external',url),
 getBrowserSettings:()=>ipcRenderer.invoke('vault:browser-settings'),setBrowserEnabled:value=>ipcRenderer.invoke('vault:browser-enable',value),openExtensionFolder:()=>ipcRenderer.invoke('vault:extension-folder'),
 onBrowserRequest(handler){if(typeof handler!=='function')throw new Error('浏览器处理函数无效');const receive=async(_event,{id,request})=>{let response;try{response={ok:true,result:await handler(request)};}catch(error){response={ok:false,error:{code:typeof error?.code==='string'?error.code:'request_failed',message:typeof error?.message==='string'?error.message:'浏览器操作未完成。'}};}ipcRenderer.send('vault:browser-response',{id,response});};ipcRenderer.on('vault:browser-request',receive);ipcRenderer.send('vault:browser-ready');return()=>ipcRenderer.removeListener('vault:browser-request',receive);},
 onBrowserSettings(handler){const receive=(_event,value)=>handler(value);ipcRenderer.on('vault:browser-settings-changed',receive);return()=>ipcRenderer.removeListener('vault:browser-settings-changed',receive);},
});
