import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {mkdtemp,readFile,writeFile,rm,realpath} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createVault,writeRecord,parsePortableFile} from '../../core/vault.js';
import {serverEnvironment,writeServerEnvironment} from '../server-config.mjs';
import {legacyPortable} from '../legacy-file.mjs';
function fixture(){
  const profile={vaultId:randomUUID(),keyB64:randomBytes(32).toString('base64'),token:randomBytes(32).toString('base64url'),endpoint:null};
  const vault=writeRecord(createVault(profile.vaultId),null,{title:'dummy',username:'test',password:'never-send-this-password',url:'',notes:''},randomUUID());
  return {profile,vault,text:JSON.stringify({format:'private-vault-file',version:1,profile,vault})};
}
test('deployment config includes only identity and token hash, never password or key',()=>{
  const {text,profile}=fixture(),env=serverEnvironment(text);
  assert.ok(env.includes('VAULT_ID='+profile.vaultId));
  assert.ok(env.includes('VAULT_TOKEN_HASH='+createHash('sha256').update(profile.token).digest('hex')));
  for(const secret of [profile.keyB64,profile.token,'never-send-this-password'])assert.equal(env.includes(secret),false);
  assert.equal(env.trim().split('\n').length,5);
});
test('legacy restore file retains identity and credentials with zero records',()=>{
  const {profile}=fixture(),portable=parsePortableFile(legacyPortable(profile));
  assert.deepEqual(portable.profile,profile);assert.deepEqual(portable.vault.records,{});
});
test('deployment config refuses overwriting an existing server identity',async t=>{
  const parent=await realpath(os.tmpdir()),dir=await mkdtemp(path.join(parent,'pv-config-test-'));
  t.after(async()=>{const resolved=await realpath(dir);assert.equal(path.dirname(resolved),parent);assert.ok(path.basename(resolved).startsWith('pv-config-test-'));await rm(resolved,{recursive:true,force:true});});
  const input=path.join(dir,'dummy.pvault'),out=path.join(dir,'server.env');
  await writeFile(input,fixture().text);await writeServerEnvironment(input,out);const before=await readFile(out,'utf8');
  await writeFile(input,fixture().text);await assert.rejects(writeServerEnvironment(input,out),{code:'EEXIST'});
  assert.equal(await readFile(out,'utf8'),before);
});
