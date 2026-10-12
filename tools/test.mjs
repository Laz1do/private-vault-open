import { readdirSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
const root=path.resolve(import.meta.dirname,'..');
const files=[];
function collect(dir){for(const entry of readdirSync(dir,{withFileTypes:true})){const name=path.join(dir,entry.name);if(entry.isDirectory())collect(name);else if(/\.test\.(?:js|mjs|cjs)$/.test(entry.name))files.push(name);}}
for(const dir of ['core/tests','server/tests','windows/tests','tests','tools/tests']){
  try{collect(path.join(root,dir));}catch(error){if(error.code!=='ENOENT')throw error;}
}
const result=spawnSync(process.execPath,['--test','--test-isolation=none',...files.sort()],{cwd:root,stdio:'inherit'});
process.exitCode=result.status??1;
