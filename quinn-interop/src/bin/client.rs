use std::{future, net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Context};
use bytes::Bytes;
use h3::client::SendRequest;
use h3_quinn::Endpoint;
use quinn::{ClientConfig, Connection};
use rustls::{
    client::danger::ServerCertVerified,
    crypto::ring::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256},
    pki_types::{CertificateDer, ServerName, UnixTime},
    version, KeyLogFile,
};
use tokio::{self, fs::File, io::AsyncWriteExt as _, task::JoinSet};
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
    let Ok(test_case) = std::env::var("TESTCASE_CLIENT") else {
        return ();
    };
    if h3_quinn_interop::SUPPORTED_TESTS.contains(&&*test_case) {
        std::process::exit(0);
    }
    error!("Test case not supported: {test_case}");
    std::process::exit(127);
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

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

    let test_case = match std::env::var("TESTCASE") {
        Ok(x) => x,
        Err(_) => {
            error!("No test case");
            std::process::exit(127);
        }
    };

    if test_case == "http3" {
        let config = config("h3", CipherSuite::Default)?;
        let (endpoint, conn) = connect(first, config).await?;
        let res = h3_download_all(conn, &requests).await;
        endpoint.wait_idle().await;
        return res;
    }

    let suites = if test_case == "chacha20" {
        CipherSuite::Chacha20
    } else {
        CipherSuite::Default
    };
    let config = config("hq-interop", suites)?;

    if test_case == "multiconnect" {
        let mut set = JoinSet::new();
        for request in requests {
            let config = config.clone();
            set.spawn(async move {
                let (_, conn) = connect(&request, config.clone())
                    .await
                    .context("connection failed")?;
                hq_download(conn, request).await.context("request failed")?;
                Ok::<(), anyhow::Error>(())
            });
        }
        while let Some(result) = set.join_next().await {
            result.unwrap()?;
        }
        return Ok(());
    }

    let (endpoint, connection) = connect(first, config.clone()).await?;
    let connection = match test_case.as_str() {
        "zerortt" => {
            hq_download_all(connection, &requests[..1]).await?;
            endpoint.wait_idle().await;
            connect_0rtt(first, &endpoint).await?
        }
        "resumption" => {
            hq_download_all(connection, &requests[..1]).await?;
            connect_resumption(first, &endpoint).await?
        }
        _ => connection,
    };

    if test_case == "keyupdate" {
        connection.force_key_update();
    }

    let res = hq_download_all(connection, &requests).await;
    endpoint.wait_idle().await;
    res
}

enum CipherSuite {
    Default,
    Chacha20,
}

async fn hq_download_all(conn: quinn::Connection, requests: &[http::Uri]) -> anyhow::Result<()> {
    let mut set = JoinSet::new();
    for req in requests.into_iter().cloned() {
        let conn = conn.clone();
        set.spawn(async move { hq_download(conn, req).await.context("request failed") });
    }

    while let Some(result) = set.join_next().await {
        result.unwrap()?;
    }

    Ok(())
}

async fn hq_download(conn: Connection, req: http::Uri) -> anyhow::Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let hq_req = format!("GET {}\r\n", req.path());
    send.write_all(hq_req.as_bytes()).await?;
    send.finish()?;
    let mut out = File::create(format!("/downloads/{}", req.path())).await?;
    tokio::io::copy(&mut recv, &mut out).await?;
    Ok(())
}

async fn h3_download_all(conn: Connection, requests: &[http::Uri]) -> anyhow::Result<()> {
    let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await?;

    let drive = tokio::spawn(async move {
        let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
        Ok::<_, ()>(())
    });

    info!("QUIC connected ...");

    let mut set = JoinSet::new();
    for req in requests.into_iter().cloned() {
        let send_request = send_request.clone();
        set.spawn(async move {
            h3_download(send_request, req)
                .await
                .context("request failed")
        });
    }

    drive.await?.expect("driver");

    while let Some(result) = set.join_next().await {
        result.unwrap()?;
    }

    Ok(())
}

async fn h3_download(
    mut send_request: SendRequest<h3_quinn::OpenStreams, Bytes>,
    req: http::Uri,
) -> anyhow::Result<()> {
    info!("Sending request \"{}\"...", req);

    let path = format!("/downloads/{}", req.path());
    let req = http::Request::builder().uri(req).body(())?;
    let mut stream = send_request.send_request(req).await?;
    stream.finish().await?;

    info!("Receiving response ...");
    let resp = stream.recv_response().await?;

    info!("Response: {:?} {}", resp.version(), resp.status());
    info!("Headers: {:#?}", resp.headers());

    let mut out = File::create(path).await?;
    while let Some(mut chunk) = stream.recv_data().await? {
        out.write_all_buf(&mut chunk).await.expect("write_all");
        out.flush().await.expect("flush");
    }
    Ok(())
}

fn config(alpn: &str, suites: CipherSuite) -> anyhow::Result<ClientConfig> {
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
        .transport_config(h3_quinn_interop::transport_config());

    Ok(client_config)
}

async fn connect(
    uri: &http::Uri,
    client_config: ClientConfig,
) -> anyhow::Result<(Endpoint, Connection)> {
    let (addr, host) = resolve(uri).await?;

    // quinn setup
    let mut client_endpoint = h3_quinn::quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    client_endpoint.set_default_client_config(client_config);

    let new_conn = client_endpoint.connect(addr, host)?.await?;
    Ok((client_endpoint, new_conn))
}

async fn connect_resumption(uri: &http::Uri, endpoint: &Endpoint) -> anyhow::Result<Connection> {
    let (addr, host) = resolve(uri).await?;

    endpoint.connect(addr, host)?.await.map_err(Into::into)
}

async fn connect_0rtt(uri: &http::Uri, endpoint: &Endpoint) -> anyhow::Result<Connection> {
    let (addr, host) = resolve(uri).await?;

    endpoint
        .connect(addr, host)?
        .into_0rtt()
        .map(|x| x.0)
        .map_err(|_| anyhow!("0RTT failed"))
}

async fn resolve(uri: &http::Uri) -> anyhow::Result<(SocketAddr, &str)> {
    let auth = uri
        .authority()
        .ok_or_else(|| anyhow!("destination must have a host"))?;

    let port = auth.port_u16().unwrap_or(443);

    // dns me!
    let addr = tokio::net::lookup_host((auth.host(), port))
        .await?
        .next()
        .ok_or_else(|| anyhow!("dns found no addresses"))?;

    debug!("DNS Lookup for {:?}: {:?}", uri, addr);
    Ok((addr, auth.host()))
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
