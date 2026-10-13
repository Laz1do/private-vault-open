import {VaultError} from './vault.js';
const fail=(code,message)=>{throw new VaultError(code,message);};
const stamp=record=>record.versions.map(v=>v.id).sort().join('|');
function text(value,limit,required=false){if(typeof value!=='string'||value.length>limit||(required&&!value.trim()))fail('invalid_request','请检查网站、账号和密码内容。');return value;}
export function browserSite(value){text(value,2048,true);let url;try{url=new URL(value);}catch{fail('invalid_site','网站地址无效。');}if(url.protocol!=='https:'||url.username||url.password)fail('invalid_site','浏览器助手仅支持 HTTPS 网站。');return {origin:url.origin,host:url.host};}
function recordSite(record){try{return browserSite(record.entry.url).origin;}catch{return null;}}
const metadata=record=>({id:record.id,title:record.entry.title,username:record.entry.username,stamp:stamp(record)});
export function createBrowserAssistant(client,getSettings,{now=()=>Date.now(),ttl=600000,maxDrafts=20}={}){
 const drafts=new Map();let vaultId=client.snapshot().vaultId;
 const stop=client.subscribe(snapshot=>{if(snapshot.vaultId!==vaultId){vaultId=snapshot.vaultId;drafts.clear();}});
 const clearDrafts=()=>drafts.clear();
 function prune(){for(const [id,draft] of drafts)if(now()-draft.createdAt>ttl)drafts.delete(id);}
 function matches(snapshot,site){return snapshot.records.filter(record=>!record.deleted&&!record.conflict&&record.entry&&recordSite(record)===site.origin);}
 function publicDraft(draft,snapshot,withPassword=false){const records=matches(snapshot,draft.site);return {draftId:draft.id,kind:draft.kind,sourceKind:draft.sourceKind,host:draft.site.host,username:draft.username,title:draft.title,vaultId:draft.vaultId,records:records.slice(0,50).map(metadata),truncated:records.length>50,...(withPassword?{password:draft.password}:{})};}
 function getDraft(id,snapshot){text(id,80,true);prune();const draft=drafts.get(id);if(!draft)fail('draft_expired','这条待保存内容已过期，请重新提交网站表单。');if(draft.vaultId!==snapshot.vaultId)fail('stale_vault','密码库已切换，请重新检查内容。');return draft;}
 async function handleRequest(request){
  if(!request||typeof request!=='object'||Array.isArray(request)||typeof request.command!=='string')fail('invalid_request','浏览器请求无效。');
  const params=request.params??{};if(!params||typeof params!=='object'||Array.isArray(params))fail('invalid_request','浏览器请求无效。');
  const settings=await getSettings(),snapshot=client.snapshot();prune();
  if(request.command==='status')return {enabled:settings.enabled===true,browserEnabled:settings.enabled===true,vaultId:snapshot.vaultId,needsImport:snapshot.needsImport,changingVault:snapshot.changingVault===true};
  if(!settings.enabled){clearDrafts();fail('browser_disabled','请先在密码软件中启用浏览器助手。');}
  if(snapshot.needsImport)fail('needs_import','请先导入文件恢复密码库。');
  if(snapshot.changingVault)fail('vault_changing','正在保存备份并新建密码库，请稍后重试。');
  switch(request.command){
   case 'matches':{const site=browserSite(params.url),records=matches(snapshot,site);return {enabled:true,vaultId:snapshot.vaultId,records:records.slice(0,50).map(metadata),truncated:records.length>50};}
   case 'fill':{
    const site=browserSite(params.url);if(params.vaultId!==snapshot.vaultId)fail('stale_vault','密码库已切换，请重新选择账号。');
    const record=snapshot.records.find(r=>r.id===params.recordId);if(!record||record.deleted||!record.entry)fail('record_not_found','这条记录已被删除。');
    if(record.conflict)fail('conflict_requires_resolution','请先在软件中处理这条记录的冲突。');
    if(recordSite(record)!==site.origin)fail('site_mismatch','这条密码不属于当前网站。');
    if(typeof params.stamp!=='string'||params.stamp!==stamp(record))fail('stale_record','账号已更新，请重新选择。');
    return {username:record.entry.username,password:record.entry.password};
   }
   case 'stage':{
    const site=browserSite(params.url);let username=text(params.username??'',1000).trim();const password=text(params.password,4096,true);
    const sourceKind=params.kind??'login';if(!['login','register','change'].includes(sourceKind))fail('invalid_request','表单类型无效。');
    const records=matches(snapshot,site);if(!username&&records.length===1)username=records[0].entry.username;
    if(records.some(r=>r.entry.username===username&&r.entry.password===password))return {unchanged:true};
    const duplicate=[...drafts.values()].find(d=>d.vaultId===snapshot.vaultId&&d.site.origin===site.origin&&d.username===username&&d.password===password);
    if(duplicate)return publicDraft(duplicate,snapshot);
    if(drafts.size>=maxDrafts)drafts.delete(drafts.keys().next().value);
    const draft={id:crypto.randomUUID(),vaultId:snapshot.vaultId,site,username,password,title:site.host,sourceKind,kind:records.some(r=>r.entry.username===username)?'update':'new',createdAt:now(),saving:false,submitted:false};
    drafts.set(draft.id,draft);return publicDraft(draft,snapshot);
   }
   case 'draft':return publicDraft(getDraft(params.draftId,snapshot),snapshot,true);
   case 'dismiss':{getDraft(params.draftId,snapshot);drafts.delete(params.draftId);return {dismissed:true};}
   case 'confirm':{
    const draft=getDraft(params.draftId,snapshot);if(params.vaultId!==draft.vaultId)fail('stale_vault','密码库已切换，请重新检查内容。');
    if(draft.saving)fail('busy','正在保存，请稍候。');
    if(draft.submitted)fail('persistence_failed','这次修改保留在软件当前会话中，请在软件中重试保存或导出文件。');
    const username=text(params.username??draft.username,1000).trim(),password=text(params.password??draft.password,4096,true),title=text(params.title??draft.title,200,true).trim();
    let entry,recordId,expected;
    if(params.recordId===null){entry={title,username,password,url:draft.site.origin,notes:''};}
    else{
     text(params.recordId,80,true);const record=snapshot.records.find(r=>r.id===params.recordId);
     if(!record||record.deleted||record.conflict||!record.entry||recordSite(record)!==draft.site.origin)fail('stale_record','目标记录已改变，请重新选择。');
     if(typeof params.stamp!=='string'||params.stamp!==stamp(record))fail('stale_record','这条记录已更新，请重新核对后保存。');
     entry={...record.entry,username,password};recordId=record.id;expected=params.stamp;
    }
    draft.saving=true;
    try{const savedId=await client.save(entry,recordId,expected,draft.vaultId);drafts.delete(draft.id);return {saved:true,recordId:savedId};}
    catch(error){if(error.code==='persistence_failed')draft.submitted=true;throw error;}
    finally{draft.saving=false;}
   }
   default:fail('invalid_request','浏览器操作无效。');
  }
 }
 return {handleRequest,clearDrafts,dispose(){stop();clearDrafts();}};
}
