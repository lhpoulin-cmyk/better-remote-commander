import { createHash } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { createConnection } from 'node:net';
import { mkdirSync, lstatSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CONFIG_DIR } from './config.js';
import { configManager } from './config-manager.js';
import { VERSION } from './version.js';

export const HELIX_POLICY_RELEASE = 'we071-helix-bios-v1';
const EXPECTED_AGENT_VERSION = '0.2.50';
export type HelixOperation = 'preflight' | 'remount_rw' | 'transfer_manifest' | 'sync_remount_ro' | 'verify';

export function isHelixOperatorControlHost(): boolean {
  return process.platform === 'linux' && os.hostname().split('.')[0] === 'ws-hadrian' && os.userInfo().username === 'louis';
}

export function isAllowedDuringHelixGrant(toolName: string): boolean {
  return toolName === 'helix_bios_deploy';
}

type BrokerResult = Record<string, any>;
let broker: ChildProcess | null = null;
let brokerReady: Promise<void> | null = null;
let brokerFailed = false;

function runtimePaths() {
  const runtime = `/run/user/${process.getuid?.() ?? process.env.UID}`;
  const socket = path.join(runtime, 'helix-brc-operator.sock');
  const script = fileURLToPath(new URL('./helix-bios-control.py', import.meta.url));
  return { socket, script };
}

function canonicalize(value: any): any {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function policyFingerprint(config: Record<string, unknown>): string {
  const { version: _version, currentClient: _currentClient, clientHistory: _clientHistory,
    systemInfo: _systemInfo, featureFlags: _featureFlags, ...policyConfig } = config;
  const canonical = JSON.stringify(canonicalize(policyConfig));
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

async function send(action: string, extra: Record<string, unknown> = {}): Promise<BrokerResult> {
  const { socket } = runtimePaths();
  const request = JSON.stringify({ action, ...extra }) + '\n';
  return await new Promise((resolve, reject) => {
    const connection = createConnection(socket);
    let data = '';
    const timer = setTimeout(() => {
      connection.destroy();
      reject(new Error('BRC operator broker timed out'));
    }, 3000);
    connection.setEncoding('utf8');
    connection.on('connect', () => connection.write(request));
    connection.on('data', (chunk) => {
      data += chunk;
      if (data.length > 8192) {
        clearTimeout(timer);
        connection.destroy();
        reject(new Error('BRC operator broker response too large'));
        return;
      }
      if (!data.includes('\n')) return;
      clearTimeout(timer);
      connection.end();
      try {
        const response = JSON.parse(data.trim());
        if (!response.ok) reject(new Error(response.error || 'BRC operator broker refused request'));
        else resolve(response.result);
      } catch (error) {
        reject(error);
      }
    });
    connection.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function currentPolicy() {
  const config = await configManager.getConfig();
  const blocked = Array.isArray(config.blockedCommands) ? config.blockedCommands.filter((x): x is string => typeof x === 'string') : [];
  if (!['sudo', 'mount', 'umount'].every((x) => blocked.includes(x))) {
    throw new Error('Required global sudo/mount/umount blocks are not configured');
  }
  return { blocked, fingerprint: policyFingerprint(config) };
}

async function startBroker(): Promise<void> {
  if (!isHelixOperatorControlHost()) {
    throw new Error('HELIX-BIOS operator control is supported only on Linux ws-hadrian for louis');
  }
  if (VERSION !== EXPECTED_AGENT_VERSION) throw new Error('Unexpected BRC agent version; local promotion disabled');
  const { socket, script } = runtimePaths();
  const runtimeDir = path.dirname(socket);
  const runtimeStat = lstatSync(runtimeDir);
  if (runtimeStat.isSymbolicLink() || runtimeStat.uid !== process.getuid?.() || (runtimeStat.mode & 0o077) !== 0) {
    throw new Error('XDG runtime directory is not privately owned by louis');
  }
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  const configStat = lstatSync(CONFIG_DIR);
  if (configStat.isSymbolicLink() || configStat.uid !== process.getuid?.() || (configStat.mode & 0o077) !== 0) {
    throw new Error('BRC configuration directory is not private to louis');
  }
  broker = spawn('python3', [script, 'broker', '--socket', socket,
    '--state', path.join(CONFIG_DIR, 'helix-bios-operator-audit.jsonl'),
    '--agent-pid', String(process.pid), '--release', HELIX_POLICY_RELEASE,
    '--agent-version', VERSION],
  { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  const child = broker;
  brokerReady = new Promise<void>((resolve, reject) => {
    let firstLine = '';
    const timeout = setTimeout(() => reject(new Error('BRC operator broker did not start')), 5000);
    child.stdout?.on('data', (chunk: Buffer) => {
      firstLine += chunk.toString('utf8');
      const newline = firstLine.indexOf('\n');
      if (newline < 0) return;
      clearTimeout(timeout);
      try {
        const ready = JSON.parse(firstLine.slice(0, newline));
        if (ready.ready !== true || ready.release !== HELIX_POLICY_RELEASE) throw new Error('BRC operator broker release mismatch');
        resolve();
      } catch (error) { reject(error); }
    });
    child.stderr?.on('data', (chunk: Buffer) => process.stderr.write(`[brc-promote] ${chunk.toString('utf8')}`));
    child.once('error', (error) => { clearTimeout(timeout); reject(error); });
    child.once('exit', (code) => {
      if (!brokerFailed) {
        brokerFailed = true;
        broker = null;
      }
      if (code !== 0) reject(new Error(`BRC operator broker exited (${code})`));
    });
  });
  await brokerReady;
  await refreshOperatorPolicy();
}

async function ready(): Promise<void> {
  if (!brokerReady) {
    if (brokerFailed) throw new Error('BRC operator broker exited; restart the agent to restore a clean inactive state');
    await startBroker();
  }
  await brokerReady;
}

export async function refreshOperatorPolicy(): Promise<BrokerResult> {
  await ready();
  const { blocked, fingerprint } = await currentPolicy();
  return send('agent_state', { policy_release: HELIX_POLICY_RELEASE,
    policy_fingerprint: fingerprint, blocked_commands: blocked });
}

export async function authorizeHelixOperation(operation: HelixOperation): Promise<BrokerResult> {
  const { blocked, fingerprint } = await currentPolicy();
  await ready();
  return send('authorize', { policy_release: HELIX_POLICY_RELEASE,
    policy_fingerprint: fingerprint, blocked_commands: blocked, operation });
}

// Start the fail-closed broker with the agent lifecycle, not with an operator shell.
if (isHelixOperatorControlHost() && process.env.BRC_HELIX_CONTROL_DISABLE !== '1') {
  void ready().catch((error) => {
    brokerFailed = true;
    console.error(`[brc-promote] operator broker unavailable; scoped operations disabled: ${error instanceof Error ? error.message : String(error)}`);
  });
}
