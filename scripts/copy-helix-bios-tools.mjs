import { chmod, copyFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.resolve(scriptDir, '../packages/agent');
const source = path.join(packageDir, 'src/core');
const destination = path.join(packageDir, 'dist/core');

await mkdir(destination, { recursive: true });
for (const filename of ['helix-bios-control.py', 'helix-bios-install-toolkit-v1.py']) {
  await copyFile(path.join(source, filename), path.join(destination, filename));
}
await chmod(path.join(packageDir, 'bin/brc-promote'), 0o755);
await chmod(path.join(destination, 'helix-bios-control.py'), 0o755);
