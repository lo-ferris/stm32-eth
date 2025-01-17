#![no_std]
#![no_main]

//! For build and run instructions, see README.md
//!
//! A very rudimentary PTP synchronization example built using RTIC.
//!
//! The example requires that at least two nodes are running at the same time,
//! and the time synchronization that occurs does not explicitly compensate for
//! network delays.
//!
//! All nodes send traffic to a specific MAC address (AB:CD:EF:12:34:56) with an unused
//! EtherType (0xFFFF), containing nothing but the raw value of a [`Timestamp`]. Upon reception
//! of such a frame, the node will parse the timestamp, compare it to when the frame was received
//! according to the local time, and do one of following:
//!
//! 1. If the difference is larger than 20 microseconds, the current local time is set to the
//!    received value.
//! 2. If the difference is smaller than or equal to 20 microseconds, the PTP addend value is updated
//!    to compensate for the observed difference.
//!
//! When using the internal oscillator of an STM32, step 2 will (almost) never occur, as the frequency
//! drift and error with this clock is too great to accurately compensate for. However,
//! if a more accurate High Speed External oscillator is connected to your MCU, even this very basic
//! synchronization scheme can synchronize the rate of time on two nodes to within a few PPMs.
//!
//! To activate the HSE configuration for the examples, set the `STM32_ETH_EXAMPLE_HSE` environment variable
//! to `oscillator` or `bypass` when compiling examples.

use defmt_rtt as _;
use panic_probe as _;

mod common;

#[rtic::app(device = stm32_eth::stm32, dispatchers = [SPI1])]
mod app {

    use crate::common::EthernetPhy;

    use fugit::ExtU64;

    use ieee802_3_miim::{phy::PhySpeed, Phy};
    use systick_monotonic::Systick;

    use stm32_eth::{
        dma::{EthernetDMA, PacketId, RxRingEntry, TxRingEntry},
        mac::Speed,
        ptp::{EthernetPTP, Timestamp},
        Parts,
    };

    #[local]
    struct Local {}

    #[shared]
    struct Shared {
        dma: EthernetDMA<'static, 'static>,
        ptp: EthernetPTP,
        tx_id: Option<(u32, Timestamp)>,
        scheduled_time: Option<Timestamp>,
    }

    #[monotonic(binds = SysTick, default = true)]
    type Monotonic = Systick<1000>;

    #[init(local = [
        rx_ring: [RxRingEntry; 2] = [RxRingEntry::new(),RxRingEntry::new()],
        tx_ring: [TxRingEntry; 2] = [TxRingEntry::new(),TxRingEntry::new()],
    ])]
    fn init(cx: init::Context) -> (Shared, Local, init::Monotonics) {
        defmt::info!("Pre-init");
        let core = cx.core;
        let p = cx.device;

        let rx_ring = cx.local.rx_ring;
        let tx_ring = cx.local.tx_ring;

        let (clocks, gpio, ethernet) = crate::common::setup_peripherals(p);
        let mono = Systick::new(core.SYST, clocks.hclk().raw());

        defmt::info!("Setting up pins");
        let (pins, mdio, mdc, pps) = crate::common::setup_pins(gpio);

        defmt::info!("Configuring ethernet");

        let Parts { dma, mac, mut ptp } =
            stm32_eth::new_with_mii(ethernet, rx_ring, tx_ring, clocks, pins, mdio, mdc).unwrap();

        ptp.enable_pps(pps);

        defmt::info!("Enabling interrupts");
        dma.enable_interrupt();

        match EthernetPhy::from_miim(mac, 0) {
            Ok(mut phy) => {
                defmt::info!(
                    "Resetting PHY as an extra step. Type: {}",
                    phy.ident_string()
                );

                phy.phy_init();

                defmt::info!("Waiting for link up.");

                while !phy.phy_link_up() {}

                defmt::info!("Link up.");

                if let Some(speed) = phy.speed().map(|s| match s {
                    PhySpeed::HalfDuplexBase10T => Speed::HalfDuplexBase10T,
                    PhySpeed::FullDuplexBase10T => Speed::FullDuplexBase10T,
                    PhySpeed::HalfDuplexBase100Tx => Speed::HalfDuplexBase100Tx,
                    PhySpeed::FullDuplexBase100Tx => Speed::FullDuplexBase100Tx,
                }) {
                    phy.get_miim().set_speed(speed);
                    defmt::info!("Detected link speed: {}", speed);
                } else {
                    defmt::warn!("Failed to detect link speed.");
                }
            }
            Err(_) => {
                defmt::info!("Not resetting unsupported PHY. Cannot detect link speed.");
            }
        };

        sender::spawn().ok();

        (
            Shared {
                dma,
                tx_id: None,
                scheduled_time: None,
                ptp,
            },
            Local {},
            init::Monotonics(mono),
        )
    }

    #[task(shared = [dma, tx_id, ptp, scheduled_time], local = [tx_id_ctr: u32 = 0x8000_0000])]
    fn sender(cx: sender::Context) {
        sender::spawn_after(1u64.secs()).ok();

        const SIZE: usize = 42;

        // Obtain the current time to use as the "TX time" of our frame. It is clearly
        // incorrect, but works well enough in low-activity systems (such as this example).
        let now = (cx.shared.ptp, cx.shared.scheduled_time).lock(|ptp, sched_time| {
            let now = ptp.get_time();
            #[cfg(not(feature = "stm32f107"))]
            {
                let in_half_sec = now
                    + Timestamp::new(
                        false,
                        0,
                        stm32_eth::ptp::Subseconds::new_from_nanos(500_000_000).unwrap(),
                    );
                ptp.configure_target_time_interrupt(in_half_sec);
            }
            *sched_time = Some(now);

            now
        });

        const DST_MAC: [u8; 6] = [0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56];
        const SRC_MAC: [u8; 6] = [0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        const ETH_TYPE: [u8; 2] = [0xFF, 0xFF]; // Custom/unknown ethertype

        let tx_id_ctr = cx.local.tx_id_ctr;
        (cx.shared.dma, cx.shared.tx_id).lock(|dma, tx_id| {
            let tx_id_val = *tx_id_ctr;
            dma.send(SIZE, Some(PacketId(tx_id_val)), |buf| {
                // Write the Ethernet Header and the current timestamp value to
                // the frame.
                buf[0..6].copy_from_slice(&DST_MAC);
                buf[6..12].copy_from_slice(&SRC_MAC);
                buf[12..14].copy_from_slice(&ETH_TYPE);
                buf[14..22].copy_from_slice(&now.raw().to_be_bytes());
            })
            .ok();
            *tx_id = Some((tx_id_val, now));
            *tx_id_ctr += 1;
            *tx_id_ctr |= 0x8000_0000;
        });
    }

    #[task(binds = ETH, shared = [dma, tx_id, ptp, scheduled_time], priority = 2)]
    fn eth_interrupt(cx: eth_interrupt::Context) {
        (
            cx.shared.dma,
            cx.shared.tx_id,
            cx.shared.ptp,
            cx.shared.scheduled_time,
        )
            .lock(|dma, tx_id, ptp, _sched_time| {
                dma.interrupt_handler();

                #[cfg(not(feature = "stm32f107"))]
                {
                    if ptp.interrupt_handler() {
                        if let Some(sched_time) = _sched_time.take() {
                            let now = ptp.get_time();
                            defmt::info!(
                                "Got a timestamp interrupt {} seconds after scheduling",
                                now - sched_time
                            );
                        }
                    }
                }

                let mut packet_id = 0;

                while let Ok(packet) = dma.recv_next(Some(packet_id.into())) {
                    let mut dst_mac = [0u8; 6];
                    dst_mac.copy_from_slice(&packet[..6]);

                    // Note that, instead of grabbing the timestamp from the `RxPacket` directly, it
                    // is also possible to retrieve a cached version of the timestamp using
                    // `EthernetDMA::get_timestamp_for_id` (in the same way as for TX timestamps).
                    let ts = if let Some(timestamp) = packet.timestamp() {
                        timestamp
                    } else {
                        continue;
                    };

                    defmt::debug!("RX timestamp: {}", ts);

                    let timestamp = if dst_mac == [0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56] {
                        let mut timestamp_data = [0u8; 8];
                        timestamp_data.copy_from_slice(&packet[14..22]);
                        let raw = i64::from_be_bytes(timestamp_data);

                        let timestamp = Timestamp::new_raw(raw);
                        timestamp
                    } else {
                        continue;
                    };

                    defmt::debug!("Contained TX timestamp: {}", ts);

                    let diff = timestamp - ts;

                    defmt::info!("Difference between TX and RX time: {}", diff);

                    let addend = ptp.addend();
                    let nanos = diff.nanos() as u64;

                    if nanos <= 20_000 {
                        let p1 = ((nanos * addend as u64) / 1_000_000_000) as u32;

                        defmt::debug!("Addend correction value: {}", p1);

                        if diff.is_negative() {
                            ptp.set_addend(addend - p1 / 2);
                        } else {
                            ptp.set_addend(addend + p1 / 2);
                        };
                    } else {
                        defmt::warn!("Updated time.");
                        ptp.update_time(diff);
                    }

                    packet_id += 1;
                    packet_id &= !0x8000_0000;
                }

                if let Some((tx_id, sent_time)) = tx_id.take() {
                    if let Ok(ts) = dma.get_timestamp_for_id(PacketId(tx_id)) {
                        defmt::info!("TX timestamp: {}", ts);
                        defmt::debug!(
                        "Diff between TX timestamp and the time that was put into the packet: {}",
                        ts - sent_time
                    );
                    } else {
                        defmt::warn!("Failed to retrieve TX timestamp");
                    }
                }
            });
    }
}
