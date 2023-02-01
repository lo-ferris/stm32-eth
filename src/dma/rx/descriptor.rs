use core::sync::atomic::{self, Ordering};

use crate::{
    dma::{
        raw_descriptor::{DescriptorRingEntry, RawDescriptor},
        PacketId,
    },
    ptp::Timestamp,
};

use super::RxError;

/// Owned by DMA engine
const RXDESC_0_OWN: u32 = 1 << 31;
/// First descriptor
const RXDESC_0_FS: u32 = 1 << 9;
/// Last descriptor
const RXDESC_0_LS: u32 = 1 << 8;
/// Error summary
const RXDESC_0_ES: u32 = 1 << 15;
/// Frame length
const RXDESC_0_FL_MASK: u32 = 0x3FFF;
const RXDESC_0_FL_SHIFT: usize = 16;

/// Receive buffer 1 size
const RXDESC_1_RBS1_SHIFT: usize = 0;
/// Receive buffer 1 size mask
const RXDESC_1_RBS1_MASK: u32 = 0x0fff << RXDESC_1_RBS1_SHIFT;

/// Receive buffer 2 size
const RXDESC_1_RBS2_SHIFT: usize = 16;
/// Receive buffer 2 size mask
const RXDESC_1_RBS2_MASK: u32 = 0x0fff << RXDESC_1_RBS2_SHIFT;

/// Receive end of ring
const RXDESC_1_RER: u32 = 1 << 15;

#[repr(C)]
#[repr(align(4))]
#[derive(Clone, Copy)]
/// An RX DMA Descriptor.
pub struct RxDescriptor {
    inner_raw: RawDescriptor,
    packet_id: Option<PacketId>,
    #[cfg(feature = "ptp")]
    cached_timestamp: Option<Timestamp>,
}

impl Default for RxDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

impl DescriptorRingEntry for RxDescriptor {
    fn setup(&mut self, buffer: &mut [u8]) {
        self.set_buffer(buffer);
        self.set_owned();
    }
}

impl RxDescriptor {
    /// Creates a new [`RxDescriptor`].
    pub const fn new() -> Self {
        Self {
            inner_raw: RawDescriptor::new(),
            packet_id: None,
            #[cfg(feature = "ptp")]
            cached_timestamp: None,
        }
    }

    /// Is owned by the DMA engine?
    fn is_owned(&self) -> bool {
        (self.inner_raw.read(0) & RXDESC_0_OWN) == RXDESC_0_OWN
    }

    /// Pass ownership to the DMA engine
    ///
    /// Overrides old timestamp data
    pub(super) fn set_owned(&mut self) {
        // "Preceding reads and writes cannot be moved past subsequent writes."
        #[cfg(feature = "fence")]
        atomic::fence(Ordering::Release);
        atomic::compiler_fence(Ordering::Release);

        unsafe {
            self.inner_raw.modify(0, |w| w | RXDESC_0_OWN);
        }

        // Used to flush the store buffer as fast as possible to make the buffer available for the
        // DMA.
        #[cfg(feature = "fence")]
        atomic::fence(Ordering::SeqCst);
    }

    fn has_error(&self) -> bool {
        (self.inner_raw.read(0) & RXDESC_0_ES) == RXDESC_0_ES
    }

    /// Descriptor contains first buffer of frame
    fn is_first(&self) -> bool {
        (self.inner_raw.read(0) & RXDESC_0_FS) == RXDESC_0_FS
    }

    /// Descriptor contains last buffers of frame
    fn is_last(&self) -> bool {
        (self.inner_raw.read(0) & RXDESC_0_LS) == RXDESC_0_LS
    }

    /// Configure the buffer and its length.
    fn set_buffer(&mut self, buffer: &[u8]) {
        let buffer_ptr = buffer.as_ptr();
        let buffer_len = buffer.len();

        unsafe {
            self.inner_raw.modify(1, |w| {
                // If rbs1 == 0, RBS1 will be ignored
                let w = w & !(RXDESC_1_RBS1_MASK);
                // Mask out any previous value of rbs2
                let w = w & !(RXDESC_1_RBS2_MASK);
                // Set the length of RBS2
                let w = w | ((buffer_len << RXDESC_1_RBS2_SHIFT) as u32 & RXDESC_1_RBS2_MASK);
                w
            });

            self.inner_raw.write(3, buffer_ptr as u32);
        }
    }

    pub(super) fn frame_length(&self) -> usize {
        ((self.inner_raw.read(0) >> RXDESC_0_FL_SHIFT) & RXDESC_0_FL_MASK) as usize
    }

    pub(super) fn take_received(
        &mut self,
        // NOTE(allow): packet_id is unused if ptp is disabled.
        #[allow(unused_variables)] packet_id: Option<PacketId>,
    ) -> Result<(), RxError> {
        if self.is_owned() {
            Err(RxError::WouldBlock)
        } else if self.has_error() {
            self.set_owned();
            Err(RxError::DmaError)
        } else if self.is_first() && self.is_last() {
            // "Subsequent reads and writes cannot be moved ahead of preceding reads."
            atomic::compiler_fence(Ordering::Acquire);

            // Cache the PTP timestamps if PTP is enabled.
            #[cfg(feature = "ptp")]
            self.attach_timestamp(packet_id);

            Ok(())
        } else {
            self.set_owned();
            Err(RxError::Truncated)
        }
    }

    pub(super) fn set_end_of_ring(&mut self) {
        unsafe { self.inner_raw.modify(1, |w| w | RXDESC_1_RER) }
    }

    pub(super) fn packet_id(&self) -> Option<&PacketId> {
        self.packet_id.as_ref()
    }
}

#[cfg(feature = "ptp")]
impl RxDescriptor {
    /// Get PTP timestamps if available
    pub(super) fn read_timestamp(&self) -> Option<Timestamp> {
        #[cfg(not(feature = "stm32f1xx-hal"))]
        let is_valid = {
            /// RX timestamp
            const RXDESC_0_TIMESTAMP_VALID: u32 = 1 << 7;
            self.inner_raw.read(0) & RXDESC_0_TIMESTAMP_VALID == RXDESC_0_TIMESTAMP_VALID
        };

        #[cfg(feature = "stm32f1xx-hal")]
        // There is no "timestamp valid" indicator bit
        // on STM32F1XX
        let is_valid = true;

        let timestamp = Timestamp::from_descriptor(&self.inner_raw);

        if is_valid && self.is_last() {
            timestamp
        } else {
            None
        }
    }

    pub(super) fn attach_timestamp(&mut self, packet_id: Option<PacketId>) {
        if packet_id != self.packet_id {
            self.cached_timestamp.take();
        }

        if let (Some(timestamp), None) = (self.read_timestamp(), self.cached_timestamp) {
            self.cached_timestamp = Some(timestamp);
        }
    }

    pub(super) fn timestamp(&self) -> Option<&Timestamp> {
        self.cached_timestamp.as_ref()
    }
}