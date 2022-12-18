use heapless::Vec;

use super::MacAddressFilter;

/// Multicast address filtering
#[derive(Debug, Clone)]
pub enum MulticastAddressFiltering {
    /// All received multicast frames are passed to the
    /// application.
    PassAll,
    /// Only multicast frames whose destination address
    /// passes the hash table check are passed to the
    /// application.
    DestinationAddressHash,
    /// Only multicast frames whose destination address
    /// is equal to one of the provided destination addresses
    /// are passed to the application.
    DestinationAddress(Vec<MacAddressFilter, 3>),
}

impl MulticastAddressFiltering {
    /// Create a new MulticastAddressFiltering that does not
    /// filter any multicast frames.
    pub const fn new() -> Self {
        Self::PassAll
    }
}

impl Default for MulticastAddressFiltering {
    fn default() -> Self {
        Self::new()
    }
}