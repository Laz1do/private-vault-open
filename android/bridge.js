(() => {
  if(window.top!==window || window.VaultHost || !window.AndroidVault)return;
  let nextId=0;
  let capability=null;
  let activate;
  const ready=new Promise(resolve=>{activate=resolve;});
  // Native injects this capability only in the trusted main frame after loading.
  window.__vaultInstallHost=value=>{
    if(capability!==null || typeof value!=='string' || value.length<40)return;
    capability=value;delete window.__vaultInstallHost;activate();
  };
  const pending=new Map();
  window.__vaultNativeResponse=response=>{
    const item=pending.get(response.id);if(!item)return;
    pending.delete(response.id);clearTimeout(item.timeout);
    if(response.error)item.reject(new Error(response.error));else item.resolve(response.value);
  };
  function call(method,...args){
    return ready.then(()=>new Promise((resolve,reject)=>{
      const id=++nextId;
      // Document selection may remain open while the user browses or changes apps.
      const choosing=method==='chooseImportFile' || method==='saveExportFile';
      const timeout=choosing?null:setTimeout(()=>{pending.delete(id);reject(new Error('操作超时，请重试'));},60000);
      pending.set(id,{resolve,reject,timeout});
      try{window.AndroidVault.request(JSON.stringify({id,method,args,bridgeNonce:capability}));}catch(error){pending.delete(id);clearTimeout(timeout);reject(error);}
    }));
  }
  window.VaultHost=Object.freeze({getConfig:()=>call('getConfig'),readLocal:()=>call('readLocal'),writeLocal:value=>call('writeLocal',value),writeState:(config,local)=>call('writeState',config,local),chooseImportFile:()=>call('chooseImportFile'),saveExportFile:text=>call('saveExportFile',text),request:(method,path,body)=>call('request',method,path,body),copyText:text=>call('copyText',text),openExternal:url=>call('openExternal',url)});
})();
