import assert from 'node:assert/strict';
import test from 'node:test';
process.env.BRC_HELIX_CONTROL_DISABLE = '1';
const { handleHelixBiosDeploy, HELIX_BIOS_DEPLOY_TOOL } = await import('../dist/core/handlers/helix-bios-handlers.js');
const { isAllowedDuringHelixGrant } = await import('../dist/core/helix-operator-control.js');

test('fixed HELIX-BIOS tool exposes only the manifest transfer operation', () => {
  assert.equal(HELIX_BIOS_DEPLOY_TOOL.name, 'helix_bios_deploy');
  assert.equal(HELIX_BIOS_DEPLOY_TOOL.inputSchema.additionalProperties, false);
  assert.deepEqual(HELIX_BIOS_DEPLOY_TOOL.inputSchema.required, ['operation']);
  assert.deepEqual(HELIX_BIOS_DEPLOY_TOOL.inputSchema.properties.operation, {
    type: 'string', const: 'transfer_manifest',
  });
});

test('active grant blocks every BRC tool except the fixed deployment operation', () => {
  assert.equal(isAllowedDuringHelixGrant('helix_bios_deploy'), true);
  for (const name of ['start_process', 'interact_with_process', 'set_config_value', 'read_file', 'get_config']) {
    assert.equal(isAllowedDuringHelixGrant(name), false, `${name} must stay denied during the grant`);
  }
});

test('fixed tool rejects command, path, target, shell, and chaining arguments before authorization', async () => {
  const refused = await handleHelixBiosDeploy({
    operation: 'transfer_manifest',
    command: 'ssh hv-lore sudo mount; reboot',
    shell: '/bin/bash',
    target: 'other-host',
    uuid: 'other-media',
    source: '/tmp/other-stage',
  });
  assert.equal(refused.isError, true);
  assert.match(refused.content[0].text, /accepts only/);
});

test('fixed tool refuses operation aliases and arbitrary interpreter commands', async () => {
  for (const operation of ['install', 'ssh hv-lore sudo mount', 'python3 -c import_os', 'transfer_manifest && reboot']) {
    const refused = await handleHelixBiosDeploy({ operation });
    assert.equal(refused.isError, true);
    assert.match(refused.content[0].text, /accepts only/);
  }
});
