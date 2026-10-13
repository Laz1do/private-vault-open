import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {cwd: root, stdio: 'inherit', windowsHide: true});
    child.on('error', reject);
    child.on('exit', code => code === 0 ? resolve() : reject(new Error('Windows 构建未完成。')));
  });
}
if (process.platform !== 'win32') throw new Error('Windows 安装包需要在 Windows 上构建。');
await run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(root, 'tools/build-browser-host.ps1')]);
await run(process.execPath, [path.join(root, 'node_modules/electron-builder/cli.js'), '--win', 'nsis', '--x64']);
