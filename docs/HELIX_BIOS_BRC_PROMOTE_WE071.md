# HELIX-BIOS local deployment control (Work Entry 071)

This fork adds a fixed-function control for the approved HELIX-BIOS USB
deployment. It does not change BRC's global `sudo`, `mount`, or `umount`
blocklist and does not expose a shell command for the workflow.

## Operator flow

On Linux `ws-hadrian`, as `louis`, an interactive terminal can run the packaged
`brc-promote` command:

- `brc-promote on` asks for the exact confirmation `ENABLE WE070 HELIX-BIOS FOR
  30 MINUTES` and opens one in-memory grant, lasting at most 30 minutes.
- A connected BRC client can then invoke the fixed `helix_bios_deploy` tool. It
  takes only `{"operation":"transfer_manifest"}`. The grant permits one
  invocation; a second or concurrent invocation is denied.
- `brc-promote status` reports the current grant, expiration, and sole allowed
  operation. `brc-promote off` immediately revokes it.

The broker accepts activation and revocation only from the local Unix socket
peer running as `louis` in an interactive login session with a terminal. The
remote BRC tool has no activation, revocation, or policy-mutation endpoint. The
broker binds the grant to Lore, Work Entry 070, UUID `2AF8-4CD6`, mountpoint
`/mnt/helix-bios`, and the pinned Foundation Toolkit v1 manifest. The package
allows one fixed transfer per grant, and the dispatcher denies every other BRC
tool while a grant is active. Global command blocks remain in place.

The grant exists only in the broker process. Its monotonic deadline and wall
clock consistency check expire it independently of the terminal; the broker
also exits if the exact agent process instance that launched it ends. Agent
restart therefore starts without an active grant. Configuration drift, missing
global command blocks, unexpected policy release, or broker failure denies
remote BRC tool calls on Hadrian until policy verification succeeds.

## Deployment behavior and limits

The fixed tool verifies the packaged installer digest before starting it. The
installer accepts no host, path, shell command, UUID, or manifest override. It
uses the separately staged, Foundation-manifest-verified 25-artifact package,
the existing `hv-lore` SSH alias, and UUID-based media checks. It preserves
existing files, verifies the transfer, syncs, and restores a read-only mount.
The installer never executes HP firmware utilities.

The BRC path invokes Lore's existing `sudo -n` mechanism, so it succeeds only
when that exact administrative operation is already authorized without an
interactive password prompt. This code does not create or alter Lore sudoers
policy. The source change itself does not install or restart BRC, activate a
grant, or deploy the USB. No runtime installation or live-host execution has
been qualified by the synthetic tests in this repository.

The BRC package's license and upstream `NOTICE` remain preserved. The
manufacturer-neutral capture tools and vendor packages remain owned by
Foundation; this fork contains only the fixed transfer controller and its
installer integration.
