import { execFile } from 'node:child_process';
import { lstat, readFile, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { authorizeHelixOperation } from '../helix-operator-control.js';
import { ServerResult } from '../types.js';

const InstallArgs = z.object({ operation: z.literal('transfer_manifest') }).strict();
const INSTALLER_SHA256 = 'c88989ad1e8edcbb84ea392526827cae5cf3f916187bb86e89299e8bf873ec79';

function error(text: string): ServerResult {
  return { content: [{ type: 'text', text }], isError: true };
}

/** Executes one fixed, manifest-pinned HELIX-BIOS transfer workflow. */
export async function handleHelixBiosDeploy(args: unknown): Promise<ServerResult> {
  const parsed = InstallArgs.safeParse(args);
  if (!parsed.success) return error('HELIX-BIOS deploy accepts only {"operation":"transfer_manifest"}.');

  const capability = await authorizeHelixOperation('transfer_manifest');
  if (!capability.allowed || typeof capability.operation_token !== 'string') {
    return error('BRC_PROMOTE is inactive or the fixed transfer operation is outside the active grant.');
  }

  const script = fileURLToPath(new URL('../helix-bios-install-toolkit-v1.py', import.meta.url));
  try {
    const st = await lstat(script);
    if (!st.isFile() || st.isSymbolicLink() || st.uid !== process.getuid?.()) {
      return error('Pinned HELIX-BIOS installer is missing or unsafe.');
    }
    const resolved = await realpath(script);
    if (resolved !== script) return error('Pinned HELIX-BIOS installer path changed.');
    const bytes = await readFile(script);
    const digest = createHash('sha256').update(bytes).digest('hex');
    if (digest !== INSTALLER_SHA256) return error('Pinned HELIX-BIOS installer digest mismatch.');
  } catch {
    return error('Pinned HELIX-BIOS installer could not be verified.');
  }

  return await new Promise<ServerResult>((resolve) => {
    execFile('python3', [script, '--brc-operation', 'transfer_manifest'], {
      timeout: 10 * 60 * 1000,
      maxBuffer: 1024 * 1024,
      windowsHide: true,
      env: { ...process.env, HELIX_BRC_OPERATION_TOKEN: capability.operation_token },
    }, (cause, stdout, stderr) => {
      const output = `${stdout || ''}${stderr ? `\n${stderr}` : ''}`.trim();
      if (cause) resolve(error(`HELIX-BIOS fixed operation failed; no shell arguments were accepted. ${output || cause.message}`));
      else resolve({ content: [{ type: 'text', text: output || 'HELIX-BIOS fixed operation completed.' }] });
    });
  });
}

export const HELIX_BIOS_DEPLOY_TOOL = {
  name: 'helix_bios_deploy',
  description: 'Run the single fixed HELIX-BIOS Toolkit v1 manifest transfer to UUID 2AF8-4CD6 on hv-lore. Available only during a locally activated BRC_PROMOTE grant. It accepts no shell, path, host, command, or manifest arguments; it never executes firmware utilities.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['operation'],
    properties: { operation: { type: 'string', const: 'transfer_manifest' } },
  },
  annotations: { title: 'Install HELIX-BIOS manifest', readOnlyHint: false, destructiveHint: true, openWorldHint: false },
};
