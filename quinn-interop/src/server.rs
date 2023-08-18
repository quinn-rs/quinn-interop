use std::sync::Arc;
use std::{io::Cursor, path::PathBuf};

use bytes::{Bytes, BytesMut};
use h3::{quic::BidiStream, server::RequestStream};
use http::{Request, StatusCode};
use quinn::{crypto::rustls::HandshakeData, Connection};
use rustls::{Certificate, KeyLogFile, PrivateKey};
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
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();

    let testcase = match std::env::var("TESTCASE") {
        Ok(x) => x,
        Err(_) => {
            error!("No test case");
            std::process::exit(127);
        }
    };
    match testcase.as_str() {
        "http3"
        | "handshake"
        | "transfer"
        | "longrtt"
        | "chacha20"
        | "multiplexing"
        | "retry"
        | "resumption"
        | "zerortt"
        | "blackhole"
        | "keyupdate"
        | "ecn"
        | "amplificationlimit"
        | "handshakeloss"
        | "transferloss"
        | "handshakecorruption"
        | "transfercorruption"
        | "ipv6"
        | "goodput"
        | "crosstraffic" => {}
        tc => {
            error!("Test case not supported: {}", tc);
            std::process::exit(127);
        }
    }

    let (cert, key) = load_crypto().await?;
    let mut crypto = rustls::ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    crypto.max_early_data_size = u32::MAX;
    crypto.alpn_protocols = ALPN.iter().map(|a| a[..].to_vec()).collect();
    crypto.key_log = Arc::new(KeyLogFile::new());
    let mut server_config = h3_quinn::quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.use_retry(testcase == "retry");

    let addr = "[::]:443".parse()?;
    let endpoint = quinn::Endpoint::server(server_config, addr)?;

    info!(
        "Listening on port {:?}",
        endpoint.local_addr().unwrap().port()
    );

    while let Some(mut new_conn) = endpoint.accept().await {
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

async fn load_crypto() -> Result<(Certificate, PrivateKey), Box<dyn std::error::Error>> {
    let mut cert_file = File::open("/certs/cert.pem").await?;
    let mut key_file = File::open("/certs/priv.key").await?;
    let mut cert_buf = Vec::new();
    let mut key_buf = Vec::new();
    cert_file.read_to_end(&mut cert_buf).await?;
    key_file.read_to_end(&mut key_buf).await?;

    let certs = rustls_pemfile::certs(&mut Cursor::new(cert_buf))?
        .into_iter()
        .map(rustls::Certificate)
        .next()
        .ok_or_else(|| "no cert found".to_string())?;
    let key = rustls_pemfile::pkcs8_private_keys(&mut Cursor::new(key_buf))?
        .into_iter()
        .map(rustls::PrivateKey)
        .next()
        .ok_or_else(|| "no keys found".to_string())?;

    Ok((certs, key))
}
