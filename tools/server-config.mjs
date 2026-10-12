import { readFile, open, unlink, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { parsePortableFile } from '../core/vault.js';

export function serverEnvironment(text){
  const {profile}=parsePortableFile(text);
  return `VAULT_ID=${profile.vaultId}\nVAULT_TOKEN_HASH=${createHash('sha256').update(profile.token,'utf8').digest('hex')}\nVAULT_DATA_DIR=/data\nHOST=0.0.0.0\nPORT=8787\n`;
}
export async function writeServerEnvironment(input,output){
  const content=serverEnvironment(await readFile(input,'utf8'));
  await mkdir(path.dirname(path.resolve(output)),{recursive:true});
  const handle=await open(output,'wx',0o600);
  let success=false;
  try{await handle.writeFile(content,'utf8');await handle.sync();success=true;}
  finally{await handle.close();if(!success)await unlink(output).catch(()=>{});}
}
async function run(){
  const args=process.argv.slice(2);
  if(args.length!==4 || args[0]!=='--file' || args[2]!=='--out')throw new Error('用法：node tools/server-config.mjs --file 密码库.pvault --out server/server.env');
  await writeServerEnvironment(args[1],args[3]);
  console.log('已生成服务器配置（仅库 ID 和 token 摘要）；密码文件和密钥留在本机。');
}
if(import.meta.url===pathToFileURL(path.resolve(process.argv[1]??'')).href){
  try{await run();}catch(error){console.error(error.code==='EEXIST'?'目标配置已存在，未覆盖。':error.message);process.exitCode=1;}
}
