#![no_main]
#![no_std]

use ariel_os::cell::StaticCell;
use ariel_os::debug::log::debug;
use ariel_os::reexports::embassy_net::{Stack, StackResources};
use ariel_os::reexports::{embassy_executor, embassy_net};
use ariel_os::{asynch, net};
use ariel_os_wireguard::{Config, Runner};
use boringtun::x25519::{PublicKey, StaticSecret};
use core::net::SocketAddr;

#[embassy_executor::task]
async fn net_task(
    mut runner: embassy_net::Runner<'static, ariel_os_wireguard::Device<'static>>,
) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn wireguard_task(stack: Stack<'static>, mut runner: Runner<'static>) -> ! {
    let config = Config {
        private_key: StaticSecret::from(data_encoding_macro::base64!(
            "c3RhdGlvbm1hcmt0YXN0ZWNodXJjaHN0ZXB6ZWJyYXM="
        )),
        endpoint_public_key: PublicKey::from(data_encoding_macro::base64!(
            "c3RhdGlvbm1hcmt0YXN0ZWNodXJjaHN0ZXB6ZWJyYXM="
        )),
        preshared_key: None,
        endpoint_addr: SocketAddr::from(([192, 168, 0, 34], 51820)),
        endpoint_bind_addr: SocketAddr::from(([127, 0, 0, 1], 1234)),
        keepalive_seconds: None,
    };

    runner.run(stack, &config).await.unwrap();
    unreachable!()
}

#[ariel_os::task(autostart)]
async fn main_task() {
    let spawner = asynch::Spawner::for_current_executor().await;
    // Launch network task
    let stack = net::network_stack().await.unwrap();

    // Init network device
    static STATE: StaticCell<ariel_os_wireguard::State<4, 4>> = StaticCell::new();
    let state = STATE.init(ariel_os_wireguard::State::<4, 4>::new());
    let (device, runner) = ariel_os_wireguard::new(state);

    // Generate random seed
    let seed = rand_core::RngCore::next_u64(&mut ariel_os::random::crypto_rng());
    debug!("Network stack seed: {:#x}", seed);

    // Init network stack
    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    let (wireguard_stack, net_runner) = embassy_net::new(
        device,
        embassy_net::Config::default(), // don't configure IP yet
        RESOURCES.init(StackResources::new()),
        seed,
    );

    spawner.spawn(net_task(net_runner)).unwrap();
    spawner.spawn(wireguard_task(stack, runner)).unwrap();
}
