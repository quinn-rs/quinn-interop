use std::{convert::TryInto, sync::Arc, time::Duration};

use futures::future;
use h3_quinn::Endpoint;
use quinn::{ClientConfig, Connection};
use rustls::{
    client::danger::ServerCertVerified,
    crypto::ring::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256},
    pki_types::{CertificateDer, ServerName, UnixTime},
    version, KeyLogFile,
};
use tokio::{self, fs::File, io::AsyncWriteExt as _};
use tracing::{debug, error, info};

/// Tell the interop runner whether we implement this testcase or not
///
/// The interop runner checks which testcases are implemented by first running the
/// client with TESTCASE_CLIENT defined in env. If it is implemented, it expects us
/// to exit with 0. Else, we should exit with 127.
///
/// TESTCASE_CLIENT is only used to check if the test is implemented. The real test
/// will happen on a subsequent run, with TESTCASE defined.
fn test_case_implemented_or_exit() {
    match std::env::var("TESTCASE_CLIENT")
        .as_ref()
        .map(String::as_str)
    {
        Ok("http3")
        | Ok("handshake")
        | Ok("transfer")
        | Ok("longrtt")
        | Ok("chacha20")
        | Ok("multiplexing")
        | Ok("retry")
        | Ok("resumption")
        | Ok("zerortt")
        | Ok("blackhole")
        | Ok("keyupdate")
        | Ok("ecn")
        | Ok("amplificationlimit")
        | Ok("handshakeloss")
        | Ok("transferloss")
        | Ok("handshakecorruption")
        | Ok("transfercorruption")
        | Ok("ipv6")
        | Ok("goodput") => std::process::exit(0),
        Ok(tc) => {
            error!("Test case not supported: {}", tc);
            std::process::exit(127);
        }
        _ => (), // Probably a real testcase run
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();

    for (name, val) in std::env::vars() {
        println!("env: {}={}", name, val);
    }

    test_case_implemented_or_exit();

    let requests = match std::env::var("REQUESTS") {
        Err(_) => std::process::exit(127),
        Ok(r) => r
            .split_whitespace()
            .map(|x| {
                x.parse::<http::Uri>().unwrap_or_else(|e| {
                    error!("failed to parse uri: {}", e);
                    std::process::exit(127);
                })
            })
            .collect::<Vec<_>>(),
    };

    let first = if let Some(first) = requests.get(0) {
        first
    } else {
        error!("no requests");
        std::process::exit(127);
    };

    match std::env::var("TESTCASE").as_ref().map(String::as_str) {
        Ok("http3") => {
            let config = config("h3", CipherSuite::Default)?;
            let (endpoint, conn) = connect(first, config).await?;
            let res = h3_download_all(conn, &requests).await;
            endpoint.wait_idle().await;
            res
        }
        Ok(tc @ "handshake")
        | Ok(tc @ "transfer")
        | Ok(tc @ "longrtt")
        | Ok(tc @ "chacha20")
        | Ok(tc @ "multiplexing")
        | Ok(tc @ "retry")
        | Ok(tc @ "resumption")
        | Ok(tc @ "zerortt")
        | Ok(tc @ "blackhole")
        | Ok(tc @ "ecn")
        | Ok(tc @ "amplificationlimit")
        | Ok(tc @ "handshakeloss")
        | Ok(tc @ "transferloss")
        | Ok(tc @ "handshakecorruption")
        | Ok(tc @ "transfercorruption")
        | Ok(tc @ "ipv6")
        | Ok(tc @ "goodput")
        | Ok(tc @ "keyupdate")
        | Ok(tc @ "crosstraffic") => {
            let suites = if tc == "chacha20" {
                CipherSuite::Chacha20
            } else {
                CipherSuite::Default
            };
            let config = config("hq-interop", suites)?;

            let (endpoint, connection) = connect(first, config.clone()).await?;
            let connection = match tc {
                "zerortt" => {
                    hq_download_all(connection, &requests[..1]).await?;
                    connect_0rtt(first, &endpoint).await?
                }
                "resumption" => {
                    hq_download_all(connection, &requests[..1]).await?;
                    connect_resumption(first, &endpoint).await?
                }
                _ => connection,
            };

            if tc == "keyupdate" {
                connection.force_key_update();
            }

            let res = hq_download_all(connection, &requests).await;
            endpoint.wait_idle().await;
            res
        }
        tc => {
            error!("Test case not supported: {:?}", tc);
            std::process::exit(127);
        }
    }
}

enum CipherSuite {
    Default,
    Chacha20,
}

async fn hq_download_all(
    conn: quinn::Connection,
    requests: &[http::Uri],
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO spawn
    future::try_join_all(requests.into_iter().cloned().map(move |req| {
        let conn = conn.clone();
        tokio::spawn(async move {
            let mut out = File::create(format!("/downloads/{}", req.path())).await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            let hq_req = format!("GET {}\r\n", req.path());
            send.write_all(hq_req.as_bytes()).await?;
            send.finish()?;
            tokio::io::copy(&mut recv, &mut out).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
    }))
    .await?;

    Ok(())
}

async fn h3_download_all(
    conn: Connection,
    requests: &[http::Uri],
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await?;

    let drive = tokio::spawn(async move {
        let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
        Ok::<_, ()>(())
    });

    info!("QUIC connected ...");

    future::try_join_all(requests.into_iter().cloned().map(move |req| {
        let mut send_request = send_request.clone();
        tokio::spawn(async move {
            info!("Sending request \"{}\"...", req);

            let mut out = File::create(format!("/downloads/{}", req.path())).await?;
            let req = http::Request::builder().uri(req).body(())?;
            let mut stream = send_request.send_request(req).await?;
            stream.finish().await?;

            info!("Receiving response ...");
            let resp = stream.recv_response().await?;

            info!("Response: {:?} {}", resp.version(), resp.status());
            info!("Headers: {:#?}", resp.headers());

            while let Some(mut chunk) = stream.recv_data().await? {
                out.write_all_buf(&mut chunk).await.expect("write_all");
                out.flush().await.expect("flush");
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
    }))
    .await?;

    drive.await?.expect("driver");

    Ok(())
}

fn config(alpn: &str, suites: CipherSuite) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut provider = rustls::crypto::ring::default_provider();
    if let CipherSuite::Chacha20 = suites {
        provider.cipher_suites = vec![TLS13_CHACHA20_POLY1305_SHA256];
    }
    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(YesVerifier))
        .with_no_client_auth();

    tls_config.enable_early_data = true;
    tls_config.alpn_protocols = vec![alpn.into()];
    tls_config.key_log = Arc::new(KeyLogFile::new());

    let mut transport_config = quinn::TransportConfig::default();
    transport_config
        .max_idle_timeout(Some(Duration::from_millis(9000).try_into()?))
        .initial_rtt(Duration::from_millis(100));
    let tls_config = quinn::crypto::rustls::QuicClientConfig::with_initial(
        Arc::new(tls_config),
        TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap(),
    )?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(tls_config));
    client_config
        .version(0x00000001)
        .transport_config(Arc::new(transport_config));

    Ok(client_config)
}

async fn connect(
    uri: &http::Uri,
    client_config: ClientConfig,
) -> Result<(Endpoint, Connection), Box<dyn std::error::Error>> {
    let auth = uri
        .authority()
        .ok_or("destination must have a host")?
        .clone();

    let port = auth.port_u16().unwrap_or(443);

    // dns me!
    let addr = tokio::net::lookup_host((auth.host(), port))
        .await?
        .next()
        .ok_or("dns found no addresses")?;

    debug!("DNS Lookup for {:?}: {:?}", uri, addr);

    // quinn setup
    let mut client_endpoint = h3_quinn::quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    client_endpoint.set_default_client_config(client_config);

    let new_conn = client_endpoint.connect(addr, auth.host())?.await?;
    Ok((client_endpoint, new_conn))
}

async fn connect_resumption(
    uri: &http::Uri,
    endpoint: &Endpoint,
) -> Result<Connection, Box<dyn std::error::Error>> {
    let auth = uri
        .authority()
        .ok_or("destination must have a host")?
        .clone();

    let port = auth.port_u16().unwrap_or(443);

    // dns me!
    let addr = tokio::net::lookup_host((auth.host(), port))
        .await?
        .next()
        .ok_or("dns found no addresses")?;

    debug!("DNS Lookup for {:?}: {:?}", uri, addr);

    endpoint
        .connect(addr, auth.host())?
        .await
        .map_err(Into::into)
}

async fn connect_0rtt(
    uri: &http::Uri,
    endpoint: &Endpoint,
) -> Result<Connection, Box<dyn std::error::Error>> {
    let auth = uri
        .authority()
        .ok_or("destination must have a host")?
        .clone();

    let port = auth.port_u16().unwrap_or(443);

    // dns me!
    let addr = tokio::net::lookup_host((auth.host(), port))
        .await?
        .next()
        .ok_or("dns found no addresses")?;

    debug!("DNS Lookup for {:?}: {:?}", uri, addr);

    endpoint
        .connect(addr, auth.host())?
        .into_0rtt()
        .map(|x| x.0)
        .map_err(|_| "0RTT failed".to_string().into())
}

#[derive(Debug)]
struct YesVerifier;

impl rustls::client::danger::ServerCertVerifier for YesVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _scts: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
