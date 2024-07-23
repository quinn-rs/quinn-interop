use std::path::PathBuf;
use std::sync::Arc;
use std::{convert::TryFrom, io};

use bytes::{Bytes, BytesMut};
use h3::{quic::BidiStream, server::RequestStream};
use http::{Request, StatusCode};
use quinn::{crypto::rustls::HandshakeData, Connection};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    KeyLogFile,
};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, trace};

static ALPN: &[&[u8]] = &[b"h3", b"hq-interop"];
static BUF_SIZE: usize = 4096 * 1000;
static WWW: &str = "/www";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let test_case = match std::env::var("TESTCASE") {
        Ok(x) => x,
        Err(_) => {
            error!("No test case");
            std::process::exit(127);
        }
    };
    if !SUPPORTED_TESTS.contains(&&*test_case) {
        error!("Test case not supported: {}", test_case);
        std::process::exit(127);
    }

    let (certs, key) = load_crypto().await?;
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    crypto.max_early_data_size = u32::MAX;
    crypto.alpn_protocols = ALPN.iter().map(|a| a[..].to_vec()).collect();
    crypto.key_log = Arc::new(KeyLogFile::new());
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?;
    let mut transport_config = quinn::TransportConfig::default();
    // https://github.com/quic-interop/quic-interop-runner/issues/397
    transport_config
        .enable_segmentation_offload(false)
        // Don't bother probing a known network environment
        .mtu_discovery_config(None)
        // Known interface MTU, minus conservative IPv6 and UDP header sizes
        .initial_mtu(1500 - 40 - 8);
    let mut server_config = h3_quinn::quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(transport_config));

    let addr = "[::]:443".parse()?;
    let endpoint = quinn::Endpoint::server(server_config, addr)?;

    info!(
        "Listening on port {:?}",
        endpoint.local_addr().unwrap().port()
    );

    while let Some(incoming) = endpoint.accept().await {
        if test_case == "retry" && !incoming.remote_address_validated() {
            incoming.retry().unwrap();
            continue;
        }
        let mut new_conn = incoming.accept()?;
        let alpn = String::from_utf8_lossy(
            &new_conn
                .handshake_data()
                .await?
                .downcast_ref::<HandshakeData>()
                .unwrap()
                .protocol
                .as_ref()
                .unwrap()
                .clone(),
        )
        .to_string();
        trace!("New connection being attempted for {}", alpn);

        tokio::spawn(async move {
            let res = match new_conn.await {
                Ok(c) => match alpn.as_str() {
                    "h3" => serve_h3(c).await,
                    "hq-interop" => serve_hq(c).await,
                    _ => Err(format!("unsupported alpn {}", alpn).into()),
                },
                Err(e) => Err(format!("accept error {}", e).into()),
            };
            if let Err(e) = res {
                error!("{}", e);
            }
        });
    }

    endpoint.wait_idle().await;

    Ok(())
}

async fn serve_hq(conn: Connection) -> Result<(), Box<dyn std::error::Error>> {
    debug!("New connection now established");

    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        tokio::spawn(async move {
            let mut req = String::new();
            recv.read_to_string(&mut req).await.unwrap();
            let mut words = req.split(' ');
            match (words.next(), words.next()) {
                (Some("GET"), Some(path)) => {
                    let path = PathBuf::from(WWW).join(path.trim_start_matches('/').trim_end());
                    info!("serving {}", path.display());

                    match File::open(&path).await {
                        Ok(mut file) => {
                            tokio::io::copy(&mut file, &mut send).await.unwrap();
                        }
                        Err(e) => error!("opening \"{}\": {}", path.display(), e),
                    }
                }
                (m, p) => error!("invalid request {:?} {:?}", m, p),
            }
            debug!("connection requested: {:#?}", req);
        });
    }
    Ok(())
}

async fn serve_h3(conn: Connection) -> Result<(), Box<dyn std::error::Error>> {
    debug!("New connection now established");

    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();

    while let Some((req, stream)) = h3_conn.accept().await? {
        debug!("connection requested: {:#?}", req);

        tokio::spawn(async {
            if let Err(e) = handle_request(req, stream).await {
                error!("request failed with: {}", e);
            }
        });
    }
    Ok(())
}

async fn handle_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    let path = PathBuf::from(WWW).join(req.uri().path().trim_start_matches('/'));
    info!("serving {}", path.display());
    let (status, to_serve) = match File::open(&path).await {
        Ok(file) => (StatusCode::OK, Some(file)),
        Err(e) => {
            error!("opening \"{}\": {}", path.display(), e);
            (StatusCode::NOT_FOUND, None)
        }
    };

    let resp = http::Response::builder().status(status).body(()).unwrap();

    match stream.send_response(resp).await {
        Ok(_) => {
            debug!("Response to connection successful");
        }
        Err(err) => {
            error!("Unable to send response to connection peer: {:?}", err);
        }
    }

    if let Some(mut file) = to_serve {
        loop {
            let mut buf = BytesMut::with_capacity(BUF_SIZE);
            if file.read_buf(&mut buf).await? == 0 {
                break;
            }
            stream.send_data(buf.freeze()).await?;
        }
    }

    Ok(stream.finish().await?)
}

async fn load_crypto(
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    let mut cert_file = File::open("/certs/cert.pem").await?;
    let mut key_file = File::open("/certs/priv.key").await?;
    let mut cert_buf = Vec::new();
    let mut key_buf = Vec::new();
    cert_file.read_to_end(&mut cert_buf).await?;
    key_file.read_to_end(&mut key_buf).await?;

    let certs = rustls_pemfile::certs(&mut &*cert_buf)
        .collect::<Result<Vec<CertificateDer<'_>>, io::Error>>()?;
    let key =
        rustls_pemfile::private_key(&mut &*key_buf)?.ok_or_else(|| "no private keys found")?;

    Ok((certs, key))
}

const SUPPORTED_TESTS: &[&str] = &[
    "http3",
    "handshake",
    "transfer",
    "longrtt",
    "chacha20",
    "multiplexing",
    "retry",
    "resumption",
    "zerortt",
    "blackhole",
    "keyupdate",
    "ecn",
    "amplificationlimit",
    "handshakeloss",
    "transferloss",
    "handshakecorruption",
    "transfercorruption",
    "ipv6",
    "goodput",
    "crosstraffic",
];
