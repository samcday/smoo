# smoo — architectural & contributor notes

This document defines the internal architecture and invariants that all contributors + agents must follow.

---

## 1. Architecture Overview

smoo consists of two halves:

* **Host** (desktop/CLI/web): provides block data to be read/written.
* **Gadget** (device with UDC): exposes a synthetic block device via **ublk**, serviced entirely over USB using **FunctionFS**.

USB interface has **4 endpoints**:

| Endpoint      | Direction     | Purpose             |
| ------------- | ------------- |---------------------|
| Bulk OUT      | host → gadget | read payloads       |
| Bulk IN       | gadget → host | write payloads      |
| Interrupt OUT | host → gadget | control: `Response` |
| Interrupt IN  | gadget → host | control: `Request`  |

Control messages:

* ≤ 1024 bytes
* fixed-size LE structs
* synchronous per-operation
* strict ordering required

Bulk transfers:

* carry payload bytes
* must be block-aligned

---

## 2. End-to-End I/O Flow

1. ublk on gadget emits a command
2. gadget → host: send `Request` on interrupt OUT
3. host dispatches to `BlockSource`
4. host performs bulk transfers as needed
5. host → gadget: send `Response` on interrupt IN
6. gadget completes ublk request

**Invariant:** each ublk request maps to **exactly one Request + one Response**.

---

## 3. ublk Behaviour (gadget side)

* registers a ublk queue with:

  * **logical block size** (must match BlockSource)
  * **queue depth** (configurable later)
* maps each ublk command → protocol Request
* completes requests deterministically

Error handling:

* transport failures → ublk ops fail with `errno`
* fatal errors → gadget tears down ublk cleanly

---

## 4. USB Protocol (control + data)

Protocol handshake (`Ident`):
* a setup IN message (from gadget -> host)
* fixed-size, LE
* fields:
  * protocol version (major + minor)

Control-plane (`Request` / `Response`):

* fixed-size, LE
* fields:

  * op: read/write/flush/discard
  * LBA
  * byte length (block-aligned)
  * flags (future)
* MUST fit in one interrupt transfer
* MUST be delivered in-order

Data (bulk):

* write path: host → gadget (bulk OUT)
* read path: gadget → host (bulk IN)
* MUST send exactly the payload size described in Request

---

## 5. DMA-BUF Fast Path

If FunctionFS DMA-BUF support exists, the gadget:

* allocates dma-buf buffers from system dma-heap
* attaches them to FunctionFS' bulk endpoint file descriptors (`FUNCTIONFS_DMABUF_ATTACH` ioctl)
* initiates read/write transfers using these buffers (`FUNCTIONFS_DMABUF_TRANSFER` ioctl)
* copies the dma-bufs dma sync fences after transfer (`DMA_BUF_IOCTL_EXPORT_SYNC_FILE`)
* `poll`s the fence to detect completion

Properties:

* gracefully falls back if system dma-heap not present, or buffer attachments to FunctionFS endpoints fail
* nearly zero-copy
* lower CPU load
* higher throughput

---

## 6. Fallback Path (non-DMA-BUF)

If DMA-BUF fast path is unavailable:

* gadget uses classic `read()`/`write()` on bulk ep fds
* incurs at most one extra copy
* MUST preserve identical semantics to DMA-BUF mode

---

## 7. Host-Side Abstractions

### 7.1 `Transport`

Responsible for shuttling control + payload data.

**Requirements:**

* MUST preserve strict ordering (interrupt + bulk)
* MUST be cancellation-safe
* MUST be async-first (Tokio)
* MAY block internally if safe
* Each `read_bulk` / `write_bulk` MUST correspond to one payload for one ublk op

Implementations:

* `smoo-host-transport-rusb`
* `smoo-host-transport-webusb`

### 7.2 `BlockSource`

Backs actual storage.

**Requirements:**

* MUST expose `block_size()`
* MUST match gadget ublk block size
* MUST support async `read()` / `write()` of block-aligned regions
* SHOULD avoid copies
* MAY wrap:

  * files
  * raw devices
  * future WebUSB fetch backends

---



## 7.3 Gadget Lifecycle & Recovery (EP0 + ublk)

### EP0 Control Protocol

Two vendor control requests:

* **IDENT (IN)**: idempotent, side‑effect‑free. Returns protocol version and capability flags.
* **CONFIG_EXPORTS (OUT)**: authoritative replace of the complete export set. Payload describes all exports for this host session.

### Export Mapping

Each export entry includes:

* `export_id` (u32)
* `block_size`
* `size_bytes`
* flags (optional)

Gadget maps `export_id` → ublk device. CONFIG_EXPORTS creates/removes ublk devices to match payload. Successful CONFIG_EXPORTS MUST update the state file.

### Gadget Crash Recovery

On restart:

* If state file exists → RECOVERING: reattach ublk devices. If any fail, delete state file → COLD.
* If no state file → COLD.
* Recovery MUST NOT remove/modify ublk devices until complete.

### Host Restart Semantics

Host restart = new session:

* Host re‑issues IDENT + CONFIG_EXPORTS.
* Gadget MUST discard all existing exports/ublk devices and rebuild from payload.
* State file rewritten.

### FunctionFS Events

Gadget MUST drain ep0 events continuously:

* **BIND/UNBIND**
* **ENABLE/DISABLE**
* **SUSPEND/RESUME**
* **SETUP** (IDENT/CONFIG_EXPORTS)

Failure to service ep0 promptly leads to EP0 STALL + possible gadget reset.


## 8. Development & Testing

* Toolchain: Rust stable (MSRV TBD)
* Logging: `tracing`
* Tests: `cargo test --all`

  * uses mock transports
  * USB loopback via `dummy_hcd`
* CLIs are thin wrappers; logic in libraries
* Agents MUST uphold:

  * cancellation safety
  * ordering guarantees
  * all invariants in this document
