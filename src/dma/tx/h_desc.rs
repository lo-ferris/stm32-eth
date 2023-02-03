use core::sync::atomic::{self, Ordering};

use crate::dma::{raw_descriptor::RawDescriptor, PacketId};

#[cfg(feature = "ptp")]
use crate::ptp::Timestamp;

/// Interrupt On Completion
const TXDESC_2_IOC: u32 = 1 << 31;

/// Transmit Timestamp Enable
const TXDESC_2_TTSE: u32 = 1 << 30;

/// Buffer 2 length shift
const TXDESC_2_B2L_SHIFT: u32 = 16;
/// Buffer 2 length mask
const TXDESC_2_B2L_MASK: u32 = 0x3FFF << TXDESC_2_B2L_SHIFT;

/// VLAN Tag Insertion or Replacement shift
const TXDESC_2_VTIR_SHIFT: u32 = 14;
/// VLAN Tag Insertion or Replacement
#[repr(u32)]
#[allow(non_camel_case_types)]
enum TXDESC_2_VTIR {
    DontAdd = 0b00 << 14,
    RemoveTransmitVlanTag = 0b01 << TXDESC_2_VTIR_SHIFT,
    InsertVlanTag = 0b10 << TXDESC_2_VTIR_SHIFT,
    ReplaceVlanTag = 0b11 << TXDESC_2_VTIR_SHIFT,
}
/// VLAN Tag Insertion Or Replacement mask
const TXDESC_2_VTIR_MASK: u32 = 0b11 << TXDESC_2_VTIR_SHIFT;

/// Header or Buffer 1 length shift
const TXDESC_2_HEAD_B1L_SHIFT: u32 = 0;
/// Header or Buffer 1 length mask
const TXDESC_2_HEAD_B1L_MASK: u32 = 0x3FFF << TXDESC_2_HEAD_B1L_SHIFT;

// OWN bit
const TXDESC_3_OWN: u32 = 1 << 31;

// Context Type
const TXDESC_3_CTXT: u32 = 1 << 30;

// First descriptor
const TXDESC_3_FD: u32 = 1 << 29;

// Last descriptor
const TXDESC_3_LD: u32 = 1 << 28;

// CRC Pad Control shift
const TXDESC_3_CPC_SHIFT: u32 = 26;
/// CRC Pad Control
#[repr(u32)]
#[allow(non_camel_case_types)]
enum TXDESC_3_CPC {
    CRCAndPadInsertion = 0b00 << TXDESC_3_CPC_SHIFT,
    CRCInsertionOnly = 0b01 << TXDESC_3_CPC_SHIFT,
    Disabled = 0b10 << TXDESC_3_CPC_SHIFT,
    CRCReplacement = 0b11 << TXDESC_3_CPC_SHIFT,
}
/// CRC Pad Control mask
const TXDESC_3_CPC_MASK: u32 = 0b11 << TXDESC_3_CPC_SHIFT;

/// Checksum Insertion Control shift
const TXDESC_3_CIC_SHIFT: u32 = 16;
/// Checksum Insertion Control
#[repr(u32)]
#[allow(non_camel_case_types)]
enum TXDESC_3_CIC {
    Disabled = 0b00,
    IpHeaderOnly = 0b01,
    IpHeaderAndPayloadOnly = 0b10,
    IpHeaderAndPayloadAndPseudoHeader = 0b11,
}
/// Checksum Insertion Control mask
const TXDESC_3_CIC_MASK: u32 = 0b11 << TXDESC_3_CIC_SHIFT;

/// Packet length shift
const TXDESC_3_FL_SHIFT: u32 = 0;
/// Packet length mask
const TXDESC_3_FL_MASK: u32 = 0x3FFF << TXDESC_3_FL_SHIFT;

/// A TX DMA Ring Descriptor
#[repr(C)]
#[repr(align(4))]
#[derive(Clone, Copy)]
pub struct TxDescriptor {
    inner_raw: RawDescriptor,
    packet_id: Option<PacketId>,
    #[cfg(feature = "ptp")]
    cached_timestamp: Option<Timestamp>,
}

impl Default for TxDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

impl TxDescriptor {
    /// Creates an zeroed TxDescriptor.
    pub const fn new() -> Self {
        Self {
            inner_raw: RawDescriptor::new(),
            packet_id: None,
            #[cfg(feature = "ptp")]
            cached_timestamp: None,
        }
    }

    pub(super) fn setup(&self, _: &[u8]) {}

    pub(super) fn is_owned(&self) -> bool {
        (self.inner_raw.read(3) & TXDESC_3_OWN) == TXDESC_3_OWN
    }

    /// Pass ownership to the DMA engine
    pub(super) fn send(&mut self, packet_id: Option<PacketId>, buffer: &[u8]) {
        self.set_buffer(buffer);

        if packet_id.is_some() && cfg!(feature = "ptp") {
            unsafe {
                self.inner_raw.modify(2, |w| w | TXDESC_2_TTSE);
            }
        }

        self.packet_id = packet_id;

        // "Preceding reads and writes cannot be moved past subsequent writes."
        #[cfg(feature = "fence")]
        atomic::fence(Ordering::Release);
        atomic::compiler_fence(Ordering::Release);

        unsafe {
            self.inner_raw.modify(2, |w| w | TXDESC_2_IOC);

            let tx_len = ((buffer.len() as u32) << TXDESC_3_FL_SHIFT) & TXDESC_3_FL_MASK;

            self.inner_raw.modify(3, |w| {
                w | TXDESC_3_OWN
                    | TXDESC_3_CIC::IpHeaderAndPayloadOnly as u32
                    | TXDESC_3_FD
                    | TXDESC_3_LD
                    | tx_len
            })
        };

        // Used to flush the store buffer as fast as possible to make the buffer available for the
        // DMA.
        #[cfg(feature = "fence")]
        atomic::fence(Ordering::SeqCst);
    }

    /// Configure the buffer to use for transmitting,
    /// setting it to `buffer`.
    fn set_buffer(&mut self, buffer: &[u8]) {
        unsafe {
            let ptr = buffer.as_ptr();

            // Set buffer pointer 2 to the provided buffer.
            self.inner_raw.write(1, ptr as u32);

            self.inner_raw.modify(2, |w| {
                // If we set tbs1 to 0, the DMA will
                // ignore this buffer.
                let w = w & !TXDESC_2_HEAD_B1L_MASK;
                // Configure RBS2 as the provided buffer.
                let w = w & !TXDESC_2_B2L_MASK;
                w | ((buffer.len() as u32) << TXDESC_2_B2L_SHIFT) & TXDESC_2_B2L_MASK
            });
        }
    }

    pub(super) fn packet_id(&self) -> Option<&PacketId> {
        self.packet_id.as_ref()
    }
}

#[cfg(feature = "ptp")]
impl TxDescriptor {
    fn read_timestamp(&mut self) -> Option<Timestamp> {
        let tdes0 = self.inner_raw.read(0);

        let contains_timestamp = (tdes0 & TXDESC_0_TIMESTAMP_STATUS) == TXDESC_0_TIMESTAMP_STATUS;

        if !self.is_owned() && contains_timestamp && Self::is_last(tdes0) {
            Timestamp::from_descriptor(&self.inner_raw)
        } else {
            None
        }
    }

    pub(super) fn attach_timestamp(&mut self) {
        self.cached_timestamp = self.read_timestamp();
    }

    pub(super) fn timestamp(&self) -> Option<&Timestamp> {
        self.cached_timestamp.as_ref()
    }
}

impl TxDescriptor {
    /// The initial value for a TxDescriptor
    pub const TX_INIT: Self = Self::new();

    pub(crate) fn prepare_packet(&mut self) -> bool {
        !self.is_owned()
    }
}
