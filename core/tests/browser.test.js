import test from 'node:test';
import assert from 'node:assert/strict';
import { createBrowserAssistant, browserSite } from '../browser.js';
import { createVaultClient, createVault, writeRecord, parsePortableFile } from '../vault.js';
const KEY = Buffer.alloc(32, 21).toString('base64');
const TOKEN = 'public_browser_fixture_token_1234567';
const clone = value => structuredClone(value);
const entry = (password='fixture-secret',url='https://example.com/login',username='alice') => ({title:'Example',username,password,url,notes:'retain notes'});
const deferred = () => { let resolve; const promise=new Promise(r=>{resolve=r;});return {promise,resolve}; };
async function fixture(options={}) {
 const host={config:{vaultId:'browser-test-vault',keyB64:KEY,token:TOKEN,endpoint:null,mode:'file'},local:null,failWrites:false,
  async getConfig(){return clone(this.config);},async readLocal(){return clone(this.local);},async writeLocal(value){this.local=clone(value);},
  async writeState(config,local){if(this.failWrites)throw new Error('fixture disk failure');this.config=clone(config);this.local=clone(local);},async request(){throw new Error('unexpected network');}};
 const client=await createVaultClient(host),settings={enabled:true};
 const assistant=createBrowserAssistant(client,async()=>settings,options);
 const send=(command,params={})=>assistant.handleRequest({command,params});
 return {host,client,settings,assistant,send};
}
const draftParams=(draft,extra={})=>({draftId:draft.draftId,vaultId:draft.vaultId,recordId:null,...extra});

test('browser site policy uses precise HTTPS origins including ports and rejects credentials or plaintext sites',()=>{
 assert.deepEqual(browserSite('https://EXAMPLE.com/path?q=1#fragment'),{origin:'https://example.com',host:'example.com'});
 assert.equal(browserSite('https://example.com:8443/login').origin,'https://example.com:8443');
 for(const url of ['http://example.com','https://user:pass@example.com','file:///secret','javascript:alert(1)','not-url','https://example.com/'+ 'x'.repeat(2048)])assert.throws(()=>browserSite(url));
});

test('matching reveals account metadata only and filling requires current exact website, identity and version',async()=>{
 const f=await fixture(), id=await f.client.save(entry());
 await f.client.save(entry('subdomain','https://login.example.com'));
 await f.client.save(entry('different port','https://example.com:8443'));
 await f.client.save(entry('no website',''));
 const found=await f.send('matches',{url:'https://example.com/other'});assert.equal(found.records.length,1);
 assert.equal(found.records[0].id,id);assert.ok(!JSON.stringify(found).includes('fixture-secret'));assert.ok(!JSON.stringify(found).includes(KEY));assert.ok(!JSON.stringify(found).includes(TOKEN));assert.ok(!JSON.stringify(found).includes('retain notes'));
 const params={url:'https://example.com/login',recordId:id,vaultId:found.vaultId,stamp:found.records[0].stamp};
 assert.deepEqual(await f.send('fill',params),{username:'alice',password:'fixture-secret'});
 await assert.rejects(f.send('fill',{...params,url:'https://sub.example.com'}),{code:'site_mismatch'});
 await assert.rejects(f.send('fill',{...params,vaultId:'another-vault'}),{code:'stale_vault'});
 await f.client.save(entry('new-secret'),id);
 await assert.rejects(f.send('fill',params),{code:'stale_record'});
 await f.client.remove(id);await assert.rejects(f.send('fill',params),{code:'record_not_found'});
 f.assistant.dispose();
});

test('conflicting and deleted records are withheld from matches and cannot be filled',async()=>{
 const f=await fixture(),id=await f.client.save(entry()),file=parsePortableFile(await f.client.exportFile());
 const competing=writeRecord(file.vault,id,entry('other'),'other-device');await f.client.save(entry('local'),id);
 await f.client.importFile(JSON.stringify({...file,vault:competing}));
 assert.equal((await f.send('matches',{url:'https://example.com'})).records.length,0);
 await assert.rejects(f.send('fill',{url:'https://example.com',recordId:id,vaultId:f.client.snapshot().vaultId,stamp:'anything'}),{code:'conflict_requires_resolution'});
 const current=f.client.snapshot().records[0];await f.client.resolve(id,current.versions[0].id);await f.client.remove(id);
 assert.equal((await f.send('matches',{url:'https://example.com'})).records.length,0);f.assistant.dispose();
});

test('staging never writes, deduplicates identical candidates and requires explicit confirmation for a new password',async()=>{
 const f=await fixture(),params={url:'https://example.com/register',username:'alice',password:'new-secret',kind:'register'};
 const draft=await f.send('stage',params);assert.equal(draft.kind,'new');assert.equal(draft.sourceKind,'register');assert.equal(f.client.snapshot().records.length,0);
 assert.ok(!Object.hasOwn(draft,'password'));assert.equal((await f.send('stage',params)).draftId,draft.draftId);
 assert.equal((await f.send('draft',{draftId:draft.draftId})).password,'new-secret');
 const saved=await f.send('confirm',draftParams(draft,{title:'Chosen title',username:'edited-user',password:'edited-password'}));assert.equal(saved.saved,true);
 const stored=f.client.snapshot().records[0];assert.equal(stored.entry.title,'Chosen title');assert.equal(stored.entry.username,'edited-user');assert.equal(stored.entry.password,'edited-password');assert.equal(stored.entry.url,'https://example.com');
 await assert.rejects(f.send('confirm',draftParams(draft)),{code:'draft_expired'});f.assistant.dispose();
});

test('updates retain existing URL and notes and enforce reviewed version even if another update is queued',async()=>{
 const f=await fixture(),id=await f.client.save(entry()),draft=await f.send('stage',{url:'https://example.com/change',username:'alice',password:'changed',kind:'change'});
 assert.equal(draft.kind,'update');const target=draft.records.find(record=>record.id===id);
 await f.send('confirm',draftParams(draft,{recordId:id,stamp:target.stamp}));
 const saved=f.client.snapshot().records[0];assert.equal(saved.entry.password,'changed');assert.equal(saved.entry.notes,'retain notes');assert.equal(saved.entry.url,'https://example.com/login');
 const later=await f.send('stage',{url:'https://example.com',username:'alice',password:'later'}),original=later.records[0];
 const file=parsePortableFile(await f.client.exportFile());file.vault=writeRecord(file.vault,id,entry('incoming'),'other-device');
 const importing=f.client.importFile(JSON.stringify(file));
 const confirming=f.send('confirm',draftParams(later,{recordId:id,stamp:original.stamp}));
 await importing;await assert.rejects(confirming,{code:'stale_record'});assert.equal(f.client.snapshot().records[0].entry.password,'incoming');f.assistant.dispose();
});

test('a new-record confirmation queued after an imported library switch cannot land in the new library',async()=>{
 const f=await fixture(),draft=await f.send('stage',{url:'https://example.com',username:'old-user',password:'old-draft'});
 const file=parsePortableFile(await f.client.exportFile());file.profile.vaultId='different-browser-vault';file.vault=createVault(file.profile.vaultId);
 const started=deferred(),release=deferred(),normalWrite=f.host.writeState.bind(f.host);
 f.host.writeState=async(...args)=>{started.resolve();await release.promise;return normalWrite(...args);};
 const importing=f.client.importFile(JSON.stringify(file));await started.promise;
 const confirming=f.send('confirm',draftParams(draft));await Promise.resolve();
 release.resolve();await importing;await assert.rejects(confirming,{code:'stale_vault'});
 assert.equal(f.client.snapshot().vaultId,'different-browser-vault');assert.equal(f.client.snapshot().records.length,0);
 await assert.rejects(f.send('draft',{draftId:draft.draftId}),{code:'draft_expired'});f.assistant.dispose();
});

test('disabled helper exposes only status, clears candidates and makes no password read or write',async()=>{
 const f=await fixture(),draft=await f.send('stage',{url:'https://example.com',password:'unsaved'});f.settings.enabled=false;
 assert.equal((await f.send('status')).enabled,false);
 for(const [command,params] of [['matches',{url:'https://example.com'}],['draft',{draftId:draft.draftId}],['confirm',draftParams(draft)]])await assert.rejects(f.send(command,params),{code:'browser_disabled'});
 f.settings.enabled=true;await assert.rejects(f.send('draft',{draftId:draft.draftId}),{code:'draft_expired'});assert.equal(f.client.snapshot().records.length,0);f.assistant.dispose();
});

test('candidate expiry and bounded retention remove old secrets; dismissal and dispose remove them immediately',async()=>{
 let time=100;const f=await fixture({now:()=>time,ttl:50,maxDrafts:2});
 const a=await f.send('stage',{url:'https://a.example.com',password:'a'}),b=await f.send('stage',{url:'https://b.example.com',password:'b'}),c=await f.send('stage',{url:'https://c.example.com',password:'c'});
 await assert.rejects(f.send('draft',{draftId:a.draftId}),{code:'draft_expired'});
 await f.send('dismiss',{draftId:b.draftId});await assert.rejects(f.send('draft',{draftId:b.draftId}),{code:'draft_expired'});
 time=151;await assert.rejects(f.send('draft',{draftId:c.draftId}),{code:'draft_expired'});
 const last=await f.send('stage',{url:'https://example.com',password:'last'});f.assistant.dispose();await assert.rejects(f.send('draft',{draftId:last.draftId}),{code:'draft_expired'});
});

test('persistence failure retains one in-memory update and refuses a repeated confirmation that would invent another version',async()=>{
 const f=await fixture(),draft=await f.send('stage',{url:'https://example.com',password:'disk-failure-secret'});f.host.failWrites=true;
 await assert.rejects(f.send('confirm',draftParams(draft)),{code:'persistence_failed'});const after=await f.client.exportFile();
 assert.equal(f.client.snapshot().records.length,1);await assert.rejects(f.send('confirm',draftParams(draft)),{code:'persistence_failed'});
 assert.equal(await f.client.exportFile(),after);f.host.failWrites=false;await f.client.sync();assert.equal(f.client.snapshot().records.length,1);f.assistant.dispose();
});

test('a second confirmation during persistence is rejected rather than creating a duplicate record',async()=>{
 const f=await fixture(),draft=await f.send('stage',{url:'https://example.com',password:'one-save'}),started=deferred(),release=deferred(),normal=f.host.writeState.bind(f.host);
 f.host.writeState=async(...args)=>{started.resolve();await release.promise;return normal(...args);};
 const saving=f.send('confirm',draftParams(draft));await started.promise;
 await assert.rejects(f.send('confirm',draftParams(draft)),{code:'busy'});release.resolve();assert.equal((await saving).saved,true);
 assert.equal(f.client.snapshot().records.length,1);f.assistant.dispose();
});

test('a whole-vault backup transaction blocks browser matching, filling and confirmation while status remains available',async()=>{
 const f=await fixture(),id=await f.client.save(entry()),matched=await f.send('matches',{url:'https://example.com'}),draft=await f.send('stage',{url:'https://example.com',password:'unsaved-change'});
 const started=deferred(),release=deferred();f.host.backupAndReplace=async()=>{started.resolve();await release.promise;return false;};
 const resetting=f.client.exportAndCreateNew();await started.promise;
 assert.equal((await f.send('status')).changingVault,true);
 for(const [command,params] of [['matches',{url:'https://example.com'}],['fill',{url:'https://example.com',recordId:id,stamp:matched.records[0].stamp,vaultId:matched.vaultId}],['confirm',draftParams(draft)]])await assert.rejects(f.send(command,params),{code:'vault_changing'});
 release.resolve();assert.equal((await resetting).created,false);assert.equal((await f.send('status')).changingVault,false);f.assistant.dispose();
});

test('unchanged submitted credentials do not offer a save; ambiguous empty usernames stay explicit',async()=>{
 const f=await fixture();await f.client.save(entry());
 assert.deepEqual(await f.send('stage',{url:'https://example.com',username:'alice',password:'fixture-secret'}),{unchanged:true});
 const guessed=await f.send('stage',{url:'https://example.com',password:'updated'});assert.equal(guessed.username,'alice');
 await f.client.save(entry('second','https://example.com','bob'));
 const ambiguous=await f.send('stage',{url:'https://example.com',password:'another'});assert.equal(ambiguous.username,'');assert.equal(ambiguous.records.length,2);f.assistant.dispose();
});

test('malformed browser operations and password limits fail before creating a candidate or writing a library',async()=>{
 const f=await fixture();for(const request of [null,[],{command:1},{command:'matches',params:[]},{command:'unknown'}])await assert.rejects(f.assistant.handleRequest(request),{code:'invalid_request'});
 for(const params of [{url:'https://example.com',password:''},{url:'https://example.com',password:'x'.repeat(4097)},{url:'https://example.com',password:'p',username:'x'.repeat(1001)},{url:'https://example.com',password:'p',kind:'automatic-submit'}])await assert.rejects(f.send('stage',params),{code:'invalid_request'});
 assert.equal(f.client.snapshot().records.length,0);f.assistant.dispose();
});
