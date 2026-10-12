import { readFile, open, unlink } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createVault, parsePortableFile } from '../core/vault.js';
export function legacyPortable(profile){
  const normalized={vaultId:profile?.vaultId,keyB64:profile?.keyB64,token:profile?.token,endpoint:profile?.endpoint};
  const text=JSON.stringify({format:'private-vault-file',version:1,profile:normalized,vault:createVault(normalized.vaultId)});
  return JSON.stringify(parsePortableFile(text),null,2)+'\n';
}
async function run(){
  const args=process.argv.slice(2);
  if(args.length!==4 || args[0]!=='--profile' || args[2]!=='--out')throw new Error('用法：node tools/legacy-file.mjs --profile client-config.json --out restore.pvault');
  const text=legacyPortable(JSON.parse(await readFile(args[1],'utf8')));
  const output=await open(args[3],'wx',0o600);let ok=false;
  try{await output.writeFile(text,'utf8');await output.sync();ok=true;}finally{await output.close();if(!ok)await unlink(args[3]).catch(()=>{});}
  console.log('已生成私密恢复文件（不含密码记录）；原配置和原库未改动。');
}
if(import.meta.url===pathToFileURL(path.resolve(process.argv[1]??'')).href){try{await run();}catch(error){console.error(error.code==='EEXIST'?'恢复文件已存在，未覆盖。':error.message);process.exitCode=1;}}
