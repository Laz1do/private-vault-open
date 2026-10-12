const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('VaultHost',{
  getConfig:()=>ipcRenderer.invoke('vault:config'),
  readLocal:()=>ipcRenderer.invoke('vault:read'),
  writeLocal:(value)=>ipcRenderer.invoke('vault:write',value),
  writeState:(config,value)=>ipcRenderer.invoke('vault:state',config,value),
  chooseImportFile:()=>ipcRenderer.invoke('vault:import'),
  saveExportFile:(text)=>ipcRenderer.invoke('vault:export',text),
  request:(method,path,body)=>ipcRenderer.invoke('vault:request',method,path,body),
  copyText:(text)=>ipcRenderer.invoke('vault:copy',text),
  openExternal:(url)=>ipcRenderer.invoke('vault:external',url)
});
