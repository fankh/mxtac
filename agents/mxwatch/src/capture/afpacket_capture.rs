//! AF_PACKET + MMAP zero-copy packet capture (Linux only).
//!
//! Uses `TPACKET_V3` ring buffer for high-performance, zero-copy packet
//! capture directly from the Linux kernel without per-packet system calls.
//!
//! # Architecture
//!
//! A ring buffer — divided into fixed-size blocks — is memory-mapped into
//! both kernel and user-space address spaces.  The kernel fills blocks with
//! captured frames; once a block is complete (or a timeout fires), it is
//! handed to user-space by setting `TP_STATUS_USER` in the block descriptor.
//! User-space processes every frame in the block and returns it to the kernel
//! by clearing the status flag to `TP_STATUS_KERNEL`.
//!
//! This avoids one `read()`/`recvmsg()` system call per packet, giving
//! substantially lower CPU overhead and higher throughput compared with the
//! libpcap default capture path.
//!
//! # Requirements
//! * Linux kernel ≥ 3.2 (for `TPACKET_V3`)
//! * `CAP_NET_RAW` capability (or run as root)

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::sync::atomic::{fence, Ordering};

use chrono::{DateTime, Utc};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::capture::RawPacket;
use crate::config::CaptureConfig;

// ── Linux socket / packet constants ─────────────────────────────────────────
// Values from <linux/if_packet.h>, <sys/socket.h>, <bits/socket_type.h>.

const AF_PACKET: libc::c_int = 17;
const SOCK_RAW: libc::c_int = 3;
/// Capture every Ethernet frame type (ETH_P_ALL = 0x0003, stored in network order).
const ETH_P_ALL: u16 = 0x0003;

/// SOL_PACKET = 263  (from <asm/socket.h>)
const SOL_PACKET: libc::c_int = 263;

/// PACKET_ADD_MEMBERSHIP = 1
const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
/// PACKET_RX_RING = 5
const PACKET_RX_RING: libc::c_int = 5;
/// PACKET_VERSION = 10
const PACKET_VERSION: libc::c_int = 10;

/// Select the TPACKET_V3 ring-buffer format.
const TPACKET_V3: libc::c_int = 2;

/// Block status: kernel has finished writing; user-space may read.
const TP_STATUS_USER: u32 = 1;
/// Block status: user-space has finished reading; kernel may reuse.
const TP_STATUS_KERNEL: u32 = 0;

/// Enable promiscuous mode via PACKET_ADD_MEMBERSHIP.
const PACKET_MR_PROMISC: libc::c_ushort = 1;

/// How long `poll(2)` waits before rechecking the channel (milliseconds).
const POLL_TIMEOUT_MS: libc::c_int = 100;

// ── Kernel structures ────────────────────────────────────────────────────────
// These must exactly match the Linux UAPI definitions in
// <uapi/linux/if_packet.h>.  All structs use `#[repr(C)]` to preserve C
// field ordering and alignment.

/// `struct tpacket_req3` — configures `PACKET_RX_RING` for TPACKET_V3.
///
/// Size: 7 × u32 = 28 bytes.
#[repr(C)]
struct TpacketReq3 {
    /// Block size in bytes (must be a power of two, ≥ system page size).
    tp_block_size: libc::c_uint,
    /// Number of blocks in the ring.
    tp_block_nr: libc::c_uint,
    /// Maximum frame size hint (TPACKET_V3 is variable-length per block).
    tp_frame_size: libc::c_uint,
    /// Total number of frames (tp_block_size / tp_frame_size * tp_block_nr).
    tp_frame_nr: libc::c_uint,
    /// Block retire timeout in milliseconds (0 = wait until block is full).
    tp_retire_blk_tov: libc::c_uint,
    /// Size of private data appended to each block descriptor (0 here).
    tp_sizeof_priv: libc::c_uint,
    /// Feature request word (0 = default).
    tp_feature_req_word: libc::c_uint,
}

/// Flat representation of `struct tpacket_block_desc` (48 bytes).
///
/// The kernel defines a nested layout (`version`, `offset_to_priv`, then
/// a union containing `struct tpacket_hdr_v1`).  We flatten it here for
/// simpler pointer arithmetic while preserving the identical memory layout.
///
/// Field offsets:
/// ```text
///  0  version            u32
///  4  offset_to_priv     u32
///  8  block_status       u32   ← TP_STATUS_USER / TP_STATUS_KERNEL
/// 12  num_pkts           u32
/// 16  offset_to_first_pkt u32
/// 20  blk_len            u32
/// 24  seq_num            u64   ← __aligned_u64, 8-byte aligned ✓
/// 32  ts_first_pkt_sec   u32
/// 36  ts_first_pkt_usec  u32
/// 40  ts_last_pkt_sec    u32
/// 44  ts_last_pkt_usec   u32
/// ```
#[repr(C)]
struct TpacketBlockDesc {
    version: u32,
    offset_to_priv: u32,
    // tpacket_hdr_v1 fields (inlined from the union):
    block_status: u32,
    num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u64, // __aligned_u64 — offset 24, naturally 8-byte aligned
    ts_first_pkt_sec: u32,
    ts_first_pkt_usec: u32,
    ts_last_pkt_sec: u32,
    ts_last_pkt_usec: u32,
}

/// Flat representation of `struct tpacket3_hdr` (48 bytes).
///
/// Field offsets:
/// ```text
///  0  tp_next_offset  u32  ← bytes from this header to next (0 = last)
///  4  tp_sec          u32
///  8  tp_nsec         u32
/// 12  tp_snaplen      u32  ← captured bytes
/// 16  tp_len          u32  ← wire length
/// 20  tp_status       u32
/// 24  tp_mac          u16  ← offset from frame start to MAC header
/// 26  tp_net          u16
/// 28  rxhash          u32  ┐
/// 32  vlan_tci        u32  │ tpacket_hdr_variant1
/// 36  vlan_tpid       u16  │
/// 38  hv1_padding     u16  ┘
/// 40  tp_padding[8]   u8×8
/// ```
#[repr(C)]
struct Tpacket3Hdr {
    tp_next_offset: u32,
    tp_sec: u32,
    tp_nsec: u32,
    tp_snaplen: u32,
    tp_len: u32,
    tp_status: u32,
    tp_mac: u16,
    tp_net: u16,
    // tpacket_hdr_variant1 (inlined):
    rxhash: u32,
    vlan_tci: u32,
    vlan_tpid: u16,
    hv1_padding: u16,
    // trailing padding:
    tp_padding: [u8; 8],
}

/// `struct packet_mreq` — used with `PACKET_ADD_MEMBERSHIP` to enable
/// promiscuous mode.  Size: 16 bytes.
#[repr(C)]
struct PacketMreq {
    mr_ifindex: libc::c_int,
    mr_type: libc::c_ushort,
    mr_alen: libc::c_ushort,
    mr_address: [libc::c_uchar; 8],
}

// ── Ring-buffer handle ───────────────────────────────────────────────────────

/// Owns the `mmap`'d ring buffer and `munmap`s it on drop.
struct RingBuffer {
    ptr: *mut u8,
    size: usize,
    block_size: usize,
    block_count: usize,
    current_block: usize,
}

impl RingBuffer {
    /// Returns a raw pointer to the `TpacketBlockDesc` at block index `idx`.
    ///
    /// # Safety
    /// Caller must ensure `idx < block_count`.
    #[inline]
    unsafe fn block_desc(&self, idx: usize) -> *mut TpacketBlockDesc {
        self.ptr.add(idx * self.block_size) as *mut TpacketBlockDesc
    }
}

impl Drop for RingBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: ptr and size were obtained from a successful mmap call.
            unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.size) };
        }
    }
}

// SAFETY: RingBuffer wraps kernel-shared memory; we only ever access it from
// the single blocking thread that owns this struct.
unsafe impl Send for RingBuffer {}

// ── Socket RAII guard ────────────────────────────────────────────────────────

struct SockGuard(RawFd);

impl Drop for SockGuard {
    fn drop(&mut self) {
        // SAFETY: fd is a valid file descriptor obtained from socket(2).
        unsafe { libc::close(self.0) };
    }
}

// ── Public interface ─────────────────────────────────────────────────────────

/// Captures packets via `AF_PACKET` with `TPACKET_V3` MMAP ring buffer.
///
/// Instantiate with [`AfPacketCapture::new`] then call [`run_blocking`] in a
/// `tokio::task::spawn_blocking` context.
///
/// [`run_blocking`]: AfPacketCapture::run_blocking
pub struct AfPacketCapture {
    config: CaptureConfig,
}

impl AfPacketCapture {
    /// Create a new `AfPacketCapture` from the given capture configuration.
    pub fn new(config: &CaptureConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Run the capture loop (blocking).
    ///
    /// Captured packets are sent through `tx`.  The loop exits when:
    /// * `tx` is closed (receiver dropped), or
    /// * a non-recoverable socket error occurs.
    ///
    /// This method should be called via `tokio::task::spawn_blocking`.
    pub fn run_blocking(&self, tx: mpsc::Sender<RawPacket>) -> anyhow::Result<()> {
        let af = &self.config.afpacket;
        let block_size = af.block_size;
        let block_count = af.block_count;
        let frame_size = af.frame_size;
        let retire_tov = af.block_retire_tov_ms;

        if !block_size.is_power_of_two() {
            return Err(anyhow::anyhow!(
                "afpacket.block_size ({block_size}) must be a power of two"
            ));
        }
        if frame_size == 0 || block_size < frame_size {
            return Err(anyhow::anyhow!(
                "afpacket.frame_size ({frame_size}) must be > 0 and ≤ block_size ({block_size})"
            ));
        }

        info!(
            interface = %self.config.interface,
            block_size,
            block_count,
            frame_size,
            "Opening AF_PACKET capture"
        );

        // ── 1. Open raw AF_PACKET socket ────────────────────────────────────
        // ETH_P_ALL must be in network (big-endian) byte order.
        let proto = (ETH_P_ALL as u16).to_be() as libc::c_int;
        let sock = unsafe { libc::socket(AF_PACKET, SOCK_RAW, proto) };
        if sock < 0 {
            return Err(anyhow::anyhow!(
                "socket(AF_PACKET) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // Ensure socket is closed even on early return.
        // Drop order: RingBuffer (munmap) then SockGuard (close) — correct.
        let _sock_guard = SockGuard(sock);

        // ── 2. Select TPACKET_V3 ring-buffer format ─────────────────────────
        let version: libc::c_int = TPACKET_V3;
        let rc = unsafe {
            libc::setsockopt(
                sock,
                SOL_PACKET,
                PACKET_VERSION,
                &version as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(anyhow::anyhow!(
                "setsockopt(PACKET_VERSION=TPACKET_V3) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // ── 3. Configure RX ring buffer ──────────────────────────────────────
        let frame_nr = (block_size / frame_size) * block_count;
        let req = TpacketReq3 {
            tp_block_size: block_size as libc::c_uint,
            tp_block_nr: block_count as libc::c_uint,
            tp_frame_size: frame_size as libc::c_uint,
            tp_frame_nr: frame_nr as libc::c_uint,
            tp_retire_blk_tov: retire_tov,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };
        let rc = unsafe {
            libc::setsockopt(
                sock,
                SOL_PACKET,
                PACKET_RX_RING,
                &req as *const TpacketReq3 as *const libc::c_void,
                std::mem::size_of::<TpacketReq3>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(anyhow::anyhow!(
                "setsockopt(PACKET_RX_RING) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // ── 4. MMAP the ring buffer ─────────────────────────────────────────
        // MAP_SHARED is required; MAP_LOCKED is beneficial (prevents swap) but
        // needs CAP_IPC_LOCK.  We skip MAP_LOCKED to avoid a capability error.
        let ring_size = block_size * block_count;
        let ring_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                sock,
                0,
            )
        };
        if ring_ptr == libc::MAP_FAILED {
            return Err(anyhow::anyhow!(
                "mmap(ring buffer, {} bytes) failed: {}",
                ring_size,
                std::io::Error::last_os_error()
            ));
        }
        // RingBuffer::drop calls munmap when this goes out of scope.
        let mut ring = RingBuffer {
            ptr: ring_ptr as *mut u8,
            size: ring_size,
            block_size,
            block_count,
            current_block: 0,
        };

        // ── 5. Resolve interface index ───────────────────────────────────────
        let ifname = CString::new(self.config.interface.as_str())
            .map_err(|e| anyhow::anyhow!("invalid interface name: {e}"))?;
        let ifindex = unsafe { libc::if_nametoindex(ifname.as_ptr()) };
        if ifindex == 0 {
            return Err(anyhow::anyhow!(
                "interface '{}' not found",
                self.config.interface
            ));
        }

        // ── 6. Bind socket to the interface ─────────────────────────────────
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = AF_PACKET as libc::c_ushort;
        sll.sll_protocol = (ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = ifindex as libc::c_int;
        let rc = unsafe {
            libc::bind(
                sock,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(anyhow::anyhow!(
                "bind(AF_PACKET, {}) failed: {}",
                self.config.interface,
                std::io::Error::last_os_error()
            ));
        }

        // ── 7. Promiscuous mode ──────────────────────────────────────────────
        if self.config.promiscuous {
            let mr = PacketMreq {
                mr_ifindex: ifindex as libc::c_int,
                mr_type: PACKET_MR_PROMISC,
                mr_alen: 0,
                mr_address: [0; 8],
            };
            let rc = unsafe {
                libc::setsockopt(
                    sock,
                    SOL_PACKET,
                    PACKET_ADD_MEMBERSHIP,
                    &mr as *const PacketMreq as *const libc::c_void,
                    std::mem::size_of::<PacketMreq>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                warn!(
                    "Failed to enable promiscuous mode: {}",
                    std::io::Error::last_os_error()
                );
            } else {
                debug!("Promiscuous mode enabled on {}", self.config.interface);
            }
        }

        // BPF filters are not applied in AF_PACKET mode (userspace filtering).
        if !self.config.bpf_filter.is_empty() {
            warn!(
                bpf_filter = %self.config.bpf_filter,
                "BPF filter is not applied in AF_PACKET capture mode; all frames are delivered"
            );
        }

        info!(
            interface = %self.config.interface,
            ring_mb = ring_size / (1024 * 1024),
            "AF_PACKET MMAP capture started ({block_count} blocks × {block_size} bytes)"
        );

        // ── 8. Capture loop ──────────────────────────────────────────────────
        let mut pfd = libc::pollfd {
            fd: sock,
            events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
            revents: 0,
        };

        loop {
            // Exit if the processing pipeline has been shut down.
            if tx.is_closed() {
                info!("Packet channel closed — stopping AF_PACKET capture");
                break;
            }

            // Check whether the current block already has data without polling.
            // SAFETY: current_block < block_count is an invariant maintained below.
            let desc = unsafe { ring.block_desc(ring.current_block) };
            let block_status = unsafe { (*desc).block_status };

            if block_status & TP_STATUS_USER == 0 {
                // Block is still owned by the kernel; wait for data.
                let ret = unsafe { libc::poll(&mut pfd, 1, POLL_TIMEOUT_MS) };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue; // EINTR — retry
                    }
                    error!("poll() failed: {err}");
                    break;
                }
                // Timeout (ret == 0) or data arrived — recheck the block.
                continue;
            }

            // ── Process all frames in this block ─────────────────────────────
            // Acquire fence: guarantee we observe all kernel writes to this block
            // before reading any frame data.
            fence(Ordering::Acquire);

            let num_pkts = unsafe { (*desc).num_pkts };
            // `offset_to_first_pkt` is relative to the start of the block.
            let mut pkt_offset = unsafe { (*desc).offset_to_first_pkt } as usize;
            let block_base = desc as *const u8;

            'frames: for _ in 0..num_pkts {
                if pkt_offset == 0 {
                    break 'frames;
                }

                // SAFETY: pkt_offset is provided by the kernel and stays within
                // the mapped block.
                let frame = unsafe { &*(block_base.add(pkt_offset) as *const Tpacket3Hdr) };

                let snaplen = frame.tp_snaplen as usize;
                let mac_offset = frame.tp_mac as usize;
                let sec = frame.tp_sec;
                let nsec = frame.tp_nsec;
                let wire_len = frame.tp_len as usize;
                let next_offset = frame.tp_next_offset as usize;

                if snaplen > 0 {
                    // Copy captured bytes into an owned Vec so the block can be
                    // returned to the kernel promptly after this loop.
                    // SAFETY: mac_offset and snaplen are kernel-provided and stay
                    // within the mmap'd region.
                    let data = unsafe {
                        let data_ptr = block_base.add(pkt_offset + mac_offset);
                        std::slice::from_raw_parts(data_ptr, snaplen).to_vec()
                    };

                    let timestamp = DateTime::from_timestamp(sec as i64, nsec)
                        .unwrap_or_else(Utc::now);

                    let raw = RawPacket {
                        timestamp,
                        data,
                        length: wire_len,
                        caplen: snaplen,
                    };

                    if tx.blocking_send(raw).is_err() {
                        info!("Packet channel closed during send — stopping AF_PACKET capture");
                        // Return block to kernel before exiting.
                        unsafe { (*desc).block_status = TP_STATUS_KERNEL };
                        fence(Ordering::Release);
                        return Ok(());
                    }
                }

                // `tp_next_offset` is the distance from the current frame header
                // to the next one.  Zero means this is the last frame.
                if next_offset == 0 {
                    break 'frames;
                }
                pkt_offset += next_offset;
            }

            // ── Return block to the kernel ────────────────────────────────────
            // Release fence: all frame reads must complete before we clear the
            // status flag.
            fence(Ordering::Release);
            unsafe { (*desc).block_status = TP_STATUS_KERNEL };

            // Advance to the next block in round-robin order.
            ring.current_block = (ring.current_block + 1) % ring.block_count;
        }

        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that our Rust struct layouts match the Linux kernel ABI.
    /// These sizes are fixed by the kernel UAPI and must never change.
    #[test]
    fn test_kernel_struct_sizes() {
        assert_eq!(
            std::mem::size_of::<TpacketReq3>(),
            28,
            "TpacketReq3 must be 7×u32 = 28 bytes"
        );
        assert_eq!(
            std::mem::size_of::<Tpacket3Hdr>(),
            48,
            "Tpacket3Hdr must be 48 bytes"
        );
        assert_eq!(
            std::mem::size_of::<TpacketBlockDesc>(),
            48,
            "TpacketBlockDesc must be 48 bytes"
        );
        assert_eq!(
            std::mem::size_of::<PacketMreq>(),
            16,
            "PacketMreq must be 16 bytes"
        );
    }

    /// Verify field offsets within `TpacketBlockDesc` match the kernel layout.
    #[test]
    fn test_block_desc_field_offsets() {
        use std::mem::offset_of;
        assert_eq!(offset_of!(TpacketBlockDesc, block_status), 8);
        assert_eq!(offset_of!(TpacketBlockDesc, num_pkts), 12);
        assert_eq!(offset_of!(TpacketBlockDesc, offset_to_first_pkt), 16);
        assert_eq!(offset_of!(TpacketBlockDesc, seq_num), 24); // __aligned_u64
    }

    /// Verify field offsets within `Tpacket3Hdr` match the kernel layout.
    #[test]
    fn test_tpacket3_hdr_field_offsets() {
        use std::mem::offset_of;
        assert_eq!(offset_of!(Tpacket3Hdr, tp_snaplen), 12);
        assert_eq!(offset_of!(Tpacket3Hdr, tp_len), 16);
        assert_eq!(offset_of!(Tpacket3Hdr, tp_mac), 24);
        assert_eq!(offset_of!(Tpacket3Hdr, tp_net), 26);
        assert_eq!(offset_of!(Tpacket3Hdr, tp_padding), 40);
    }

    /// Ring-buffer index must wrap correctly after the last block.
    #[test]
    fn test_ring_index_wraps() {
        // Allocate a tiny fake buffer so we can create the struct.
        let mut buf = vec![0u8; 4096];
        let mut ring = RingBuffer {
            ptr: buf.as_mut_ptr(),
            size: 4096,
            block_size: 1024,
            block_count: 4,
            current_block: 3, // last block
        };
        // Simulate advancing past the last block.
        ring.current_block = (ring.current_block + 1) % ring.block_count;
        assert_eq!(ring.current_block, 0);
        // Prevent double-free: nullify the pointer so Drop is a no-op.
        ring.ptr = std::ptr::null_mut();
    }

    /// `AfPacketCapture::new` must not panic or fail.
    #[test]
    fn test_afpacket_capture_new() {
        use crate::config::CaptureConfig;
        let cfg = CaptureConfig::default();
        let _cap = AfPacketCapture::new(&cfg);
    }

    /// Block size validation: non-power-of-two must be rejected.
    #[test]
    fn test_run_blocking_rejects_bad_block_size() {
        use crate::config::{AfPacketConfig, CaptureConfig};
        let mut cfg = CaptureConfig::default();
        cfg.afpacket = AfPacketConfig {
            block_size: 3000, // not a power of two
            block_count: 4,
            frame_size: 2048,
            block_retire_tov_ms: 60,
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let cap = AfPacketCapture::new(&cfg);
        let result = cap.run_blocking(tx);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("power of two"), "unexpected error: {msg}");
    }
}
