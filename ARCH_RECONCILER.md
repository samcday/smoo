# Reconcilers Overview

This note captures the reconciler-shaped control planes that now drive both halves
of smoo. Each controller owns a declarative spec plus an observed state machine and
ticks forward using idempotent reconcile steps.

## Gadget Controller

* **Type:** `GadgetController` in `apps/smoo-gadget-cli`
* **Resources:** FunctionFS endpoints + `SmooUblk` devices keyed by `export_id`
* **Desired state:** derived from EP0 `CONFIG_EXPORTS`; stored as `HashMap<u32, ExportConfig>`
* **Observed state:** `ExportSlot` per export with `GadgetExportState` covering:
  `New → UblkDeviceAdded → QueuesRunning → Starting → Online → ShuttingDown → Deleted`
  plus `Recovering`/`Failed`
* **Loop:** `tokio::select!` keeps pumping pending I/O, control messages, and a periodic
  reconcile tick. Each tick refreshes ublk device state, drives creations/removals, and
  persists status/state-file snapshots when the topology changes.
* **Invariants:** Config ACKs are deferred until every desired export reports `Online`;
  failed exports are torn down before recreating; recovery finalization only proceeds after
  the desired spec confirms geometry.

## Host Controller

* **Type:** `HostController` in `apps/smoo-host-cli`
* **Resources:** USB transport (`RusbTransport`), heartbeat/status client, and the `SmooHost`
  request runner.
* **Desired state:** a persistent wish to have the transport connected/handshaked and all
  configured exports serving; backed by `ExportSourceConfig` specs.
* **Observed state machine:** `HostSessionState`:
  `Idle → Discovering → UsbReady → Configuring → WaitingStatus → Serving → TransportLost → Discovering`
  with `Shutdown` as terminal.
* **Loop:** also `tokio::select!` driven – when `Serving`, it multiplexes host I/O, heartbeat
  reception, reconcile ticks, and shutdown. Outside `Serving`, ticks keep pushing the state
  machine forward (discovery, IDENT, config, status checks).
* **Invariants:** session IDs must match after reconnection, heartbeat failures force a full
  transport recycle with exponential backoff, and shutdown drains the session runtime before
  returning.

These controllers keep the operators simple: the CLIs now just parse config, instantiate the
controller, and call `run()`, while the reconcilers continuously nudge their respective worlds
towards the desired declaration.
