#![no_main]
#![no_std]

use ariel_os::cell::StaticCell;
use ariel_os::debug::log::{debug, error, info};
use ariel_os::reexports::embassy_net::{Stack, StackResources};
use ariel_os::reexports::{embassy_executor, embassy_net};
use ariel_os::{asynch, config, net};
use ariel_os_wireguard::{Config, Runner};
use core::net::SocketAddr;
use ariel_os::debug::{exit, ExitCode};
use data_encoding_macro::base64;
use ariel_os::time::Instant;
use boringtun::x25519::{PublicKey, StaticSecret};
use embassy_net::{
    dns::DnsSocket,
    tcp::client::{TcpClient, TcpClientState},
};
use reqwless::client::{HttpClient, TlsConfig, TlsVerify};
use reqwless::request::Method;

// RFC8449: TLS 1.3 encrypted records are limited to 16 KiB + 256 bytes.
const MAX_ENCRYPTED_TLS_13_RECORD_SIZE: usize = 16640;
// Required by `embedded_tls::TlsConnection::new()`.
const TLS_READ_BUFFER_SIZE: usize = MAX_ENCRYPTED_TLS_13_RECORD_SIZE;
// Can be smaller than the read buffer (could be adjusted: trade-off between memory usage and not
// splitting large writes into multiple records).
const TLS_WRITE_BUFFER_SIZE: usize = 4096;

const TCP_BUFFER_SIZE: usize = 1024;
const HTTP_BUFFER_SIZE: usize = 1024;

const MAX_CONCURRENT_CONNECTIONS: usize = 2;

const ENDPOINT_URL: &str = config::str_from_env_or!(
    "ENDPOINT_URL",
    "https://crab.ariel-os.org",
    "endpoint to send the GET request to",
);

#[embassy_executor::task]
async fn net_task(
    mut runner: embassy_net::Runner<'static, ariel_os_wireguard::Device<'static>>,
) -> ! {
    info!("Run net_task");
    runner.run().await
}

#[embassy_executor::task]
async fn wireguard_task(stack: Stack<'static>, mut runner: Runner<'static>) -> ! {
    let config = Config {
        private_key: StaticSecret::from(base64!(
            "eLF/Dh4lfnu9eaEtNhAu3x0ItQZ18ZmU3HJ9fxiBiEQ="
        )),
        endpoint_public_key: PublicKey::from(base64!(
            "CMlGuaXfUYt4zUbc7++S2rY2B5jwhgUEzQaduzzFwnI="
        )),
        preshared_key: None,
        endpoint_addr: SocketAddr::from(([192, 168, 188, 29], 51820)),
        port: 51820,
        keepalive_seconds: None,
    };

    info!("Run wireguard_task");
    runner.run(stack, &config).await.unwrap();
    unreachable!()
}

#[ariel_os::task(autostart)]
async fn main_task() {
    info!("Hello World!");
    let spawner = asynch::Spawner::for_current_executor().await;
    info!("Time: {} µs", Instant::now().as_micros());

    // Launch network task
    let stack = net::network_stack().await.unwrap();
    info!("Network stack initialized");
    info!("Time: {} µs", Instant::now().as_micros());

    // Init network device
    static STATE: StaticCell<ariel_os_wireguard::State<4, 4>> = StaticCell::new();
    let state = STATE.init(ariel_os_wireguard::State::<4, 4>::new());
    let (device, runner) = ariel_os_wireguard::new(state);
    info!("Network device initialized");
    info!("Time: {} µs", Instant::now().as_micros());

    // Generate random seed
    let seed = rand_core::RngCore::next_u64(&mut ariel_os::random::crypto_rng());
    info!("Network stack seed: {:#x}", seed);
    info!("Time: {} µs", Instant::now().as_micros());

    // Init network stack
    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    let (wireguard_stack, net_runner) = embassy_net::new(
        device,
        embassy_net::Config::default(), // don't configure IP yet
        RESOURCES.init(StackResources::new()),
        seed,
    );
    info!("Network stack initialized");
    info!("Time: {} µs", Instant::now().as_micros());

    spawner.spawn(net_task(net_runner)).unwrap();
    info!("Network task spawned");
    info!("Time: {} µs", Instant::now().as_micros());
    spawner.spawn(wireguard_task(stack, runner)).unwrap();
    info!("Wireguard task spawned");
    info!("Time: {} µs", Instant::now().as_micros());

    let tcp_client_state =
        TcpClientState::<MAX_CONCURRENT_CONNECTIONS, TCP_BUFFER_SIZE, TCP_BUFFER_SIZE>::new();
    let tcp_client = TcpClient::new(wireguard_stack, &tcp_client_state);
    let dns_client = DnsSocket::new(stack);

    let tls_seed: u64 = rand_core::RngCore::next_u64(&mut ariel_os::random::crypto_rng());

    let mut tls_rx_buffer = [0; TLS_READ_BUFFER_SIZE];
    let mut tls_tx_buffer = [0; TLS_WRITE_BUFFER_SIZE];

    // We do not authenticate the server in this example, as that would require setting up a PSK
    // with the server.
    let tls_verify = TlsVerify::None;
    let tls_config = TlsConfig::new(tls_seed, &mut tls_rx_buffer, &mut tls_tx_buffer, tls_verify);

    let mut client = HttpClient::new_with_tls(&tcp_client, &dns_client, tls_config);

    wireguard_stack.wait_link_up().await;
    info!("Wireguard is up");
    info!("Time: {} µs", Instant::now().as_micros());

    if let Err(err) = send_http_get_request(&mut client, ENDPOINT_URL).await {
        error!(
            "Error while sending an HTTP request: {:?}",
            defmt::Debug2Format(&err)
        );
    }

    exit(ExitCode::SUCCESS);
}

async fn send_http_get_request(
    client: &mut HttpClient<'_, TcpClient<'_, MAX_CONCURRENT_CONNECTIONS>, DnsSocket<'_>>,
    url: &str,
) -> Result<(), reqwless::Error> {
    let mut http_rx_buf = [0; HTTP_BUFFER_SIZE];

    let mut handle = client.request(Method::GET, url).await?;
    let response = handle.send(&mut http_rx_buf).await?;

    info!("Response status: {}", response.status.0);

    if let Some(ref content_type) = response.content_type {
        info!("Response Content-Type: {}", content_type.as_str());
    }

    if let Ok(body) = response.body().read_to_end().await {
        if let Ok(body) = core::str::from_utf8(&body) {
            info!("Response body:\n{}", body);
        } else {
            info!("Received a response body, but it is not valid UTF-8");
        }
    } else {
        info!("No response body");
    }

    Ok(())
}