# smoo USB wire protocol

This document describes the on‑wire control/data protocol between the gadget
(device) and host. It is authoritative for message layout, sizes, and
constraints. All fields are little‑endian unless noted.

## Control plane (interrupt endpoints)

### Request (gadget → host)
Fixed 24 bytes.

| offset | size | field        | notes                          |
| ------ | ---- | ------------ | ------------------------------ |
| 0      | 1    | op           | `OpCode` (0=Read,1=Write,2=Flush,3=Discard) |
| 1..3   | 3    | reserved     | zero                           |
| 4..8   | 4    | export_id    | u32, must be non‑zero          |
| 8..16  | 8    | lba          | starting logical block address |
| 16..20 | 4    | num_blocks   | block count (not bytes)        |
| 20..24 | 4    | flags        | currently zero                 |

### Response (host → gadget)
Fixed 24 bytes.

| offset | size | field        | notes                              |
| ------ | ---- | ------------ | ---------------------------------- |
| 0      | 1    | op           | echoes request op                  |
| 1      | 1    | status       | 0=OK, else errno/host status byte  |
| 2..3   | 2    | reserved     | zero                               |
| 4..8   | 4    | export_id    | echoes request export_id           |
| 8..16  | 8    | lba          | echoes request lba                 |
| 16..20 | 4    | num_blocks   | block count serviced/attempted     |
| 20..24 | 4    | flags        | currently zero                     |

### CONFIG_EXPORTS (host → gadget, ep0 OUT)

bmRequestType: `0x41` (vendor, interface, OUT)  
bRequest: `0x02`  
Payload is versioned v0:

Header (8 bytes):
| offset | size | field    | notes                  |
| ------ | ---- | -------- | ---------------------- |
| 0..2   | 2    | version  | must be 0              |
| 2..4   | 2    | count    | number of entries      |
| 4..8   | 4    | flags    | must be zero           |

Entry (24 bytes) repeated `count` times:
| offset | size | field      | notes                                  |
| ------ | ---- | ---------- | -------------------------------------- |
| 0..4   | 4    | export_id  | u32, non‑zero, unique                  |
| 4..8   | 4    | block_size | bytes; power‑of‑two, 512..=65536       |
| 8..16  | 8    | size_bytes | total bytes; multiple of block_size    |
| 16..24 | 8    | reserved   | must be zero                           |

Payload length = 8 + 24 * count. Maximum count: 32.

Applying CONFIG_EXPORTS replaces the entire export set; anything not present
must be torn down by the gadget.

### IDENT (host → gadget, ep0 IN)

bmRequestType: `0xC1` (vendor, interface, IN)  
bRequest: `0x01`  
Payload: 8 bytes: `SMOO` magic + major/minor u16.

### STATUS (device → host, ep0 IN)

bmRequestType: `0xA1` (vendor, interface, IN)  
bRequest: `0x03`  
Payload: 16 bytes, versioned v0:
| offset | size | field        |
| ------ | ---- | ------------ |
| 0..2   | 2    | version (0)  |
| 2..4   | 2    | flags (bit0=export_active) |
| 4..8   | 4    | export_count |
| 8..16  | 8    | session_id   |

## Data plane (bulk endpoints)

Bulk payloads are block‑aligned and sized according to `num_blocks *
block_size` for the associated export. Request/Response ordering is strict:
each Request maps to exactly one Response.

## Constraints & invariants

- `export_id` is the primary key for all control/data paths.
- `num_blocks` is always in units of `block_size` for that export; neither
  Requests nor Responses carry byte lengths.
- All reserved fields must be zero; gadgets/hosts should reject payloads that
  violate version/flags/length checks.
- CONFIG_EXPORTS is an authoritative replace; partial/batch updates are not
  supported.
