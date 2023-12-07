//! Support TLS for hyper.
//!
//! This taken from the Warp project, and slightly adapted to fit our local needs.
//! For the original implementation, see here:
//! https://github.com/seanmonstar/warp/blob/master/src/tls.rs
//!
//! There is also an issue about adding server TLS support to hyper-tls:
//! https://github.com/hyperium/hyper-tls/issues/25
//!
//! I tried to get this work, following the gist of how it's done in Warp,
//! but hyper-tls uses native_tls rather than rust_tls, and this turned out
//! to be somewhat complicated.
//!
//! For Krill it should be fine to use rust_tls though, so therefore this
//! implementation was used in the end.

use std::{
    fs::File,
    future::Future,
    io::{self, BufReader, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{Certificate, KeyLogFile, ServerConfig};

use hyper::server::{
    accept::Accept,
    conn::{AddrIncoming, AddrStream},
};

const SSLKEYLOGFILE_ENV_VAR_NAME: &str = "SSLKEYLOGFILE";

pub trait Transport: AsyncRead + AsyncWrite {
    fn remote_addr(&self) -> Option<SocketAddr>;
}

impl Transport for AddrStream {
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr())
    }
}

pub(crate) struct LiftIo<T>(pub(crate) T);

impl<T: AsyncRead + Unpin> AsyncRead for LiftIo<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for LiftIo<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Transport for LiftIo<T> {
    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }
}

/// Represents errors that can occur building the TlsConfig
#[derive(Debug)]
pub(crate) enum TlsConfigError {
    Io(io::Error),
    /// An Error parsing a Pkcs8 key
    Pkcs8ParseError,
    /// An Error parsing a Rsa key
    RsaParseError,
    /// An error from an empty key
    EmptyKey,
    // /// An error from an invalid key
    // InvalidKey(TLSError),
    Rustls(tokio_rustls::rustls::Error),
}

impl std::fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsConfigError::Io(err) => err.fmt(f),
            TlsConfigError::Pkcs8ParseError => write!(f, "pkcs8 parse error"),
            TlsConfigError::RsaParseError => write!(f, "rsa parse error"),
            TlsConfigError::EmptyKey => write!(f, "key contains no private key"),
            TlsConfigError::Rustls(err) => write!(f, "rustls error: {}", err),
        }
    }
}

impl std::error::Error for TlsConfigError {}

/// Builder to set the configuration for the Tls server.
pub(crate) struct TlsConfigBuilder {
    cert: Box<dyn Read + Send + Sync>,
    key: Box<dyn Read + Send + Sync>,
}

impl std::fmt::Debug for TlsConfigBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        f.debug_struct("TlsConfigBuilder").finish()
    }
}

impl TlsConfigBuilder {
    /// Create a new TlsConfigBuilder
    pub(crate) fn new() -> TlsConfigBuilder {
        TlsConfigBuilder {
            key: Box::new(io::empty()),
            cert: Box::new(io::empty()),
        }
    }

    /// sets the Tls key via File Path, returns `TlsConfigError::IoError` if the file cannot be open
    pub(crate) fn key_path(mut self, path: impl AsRef<Path>) -> Self {
        self.key = Box::new(LazyFile {
            path: path.as_ref().into(),
            file: None,
        });
        self
    }

    /// Specify the file path for the TLS certificate to use.
    pub(crate) fn cert_path(mut self, path: impl AsRef<Path>) -> Self {
        self.cert = Box::new(LazyFile {
            path: path.as_ref().into(),
            file: None,
        });
        self
    }

    pub(crate) fn build(mut self) -> Result<ServerConfig, TlsConfigError> {
        let mut cert_rdr = BufReader::new(self.cert);
        let certs = rustls_pemfile::certs(&mut cert_rdr).map_err(TlsConfigError::Io)?;
        let cert = certs.into_iter().map(Certificate).collect();

        let key = {
            // convert it to Vec<u8> to allow reading it again if key is RSA
            let mut key_vec = Vec::new();
            self.key.read_to_end(&mut key_vec).map_err(TlsConfigError::Io)?;

            if key_vec.is_empty() {
                return Err(TlsConfigError::EmptyKey);
            }

            let mut pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut key_vec.as_slice())
                .map_err(|_| TlsConfigError::Pkcs8ParseError)?;

            if !pkcs8.is_empty() {
                pkcs8.remove(0)
            } else {
                let mut rsa = rustls_pemfile::rsa_private_keys(&mut key_vec.as_slice())
                    .map_err(|_| TlsConfigError::RsaParseError)?;

                if !rsa.is_empty() {
                    rsa.remove(0)
                } else {
                    return Err(TlsConfigError::EmptyKey);
                }
            }
        };

        let mut config = ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .map_err(TlsConfigError::Rustls)?
            .with_no_client_auth()
            .with_single_cert(cert, tokio_rustls::rustls::PrivateKey(key))
            .map_err(TlsConfigError::Rustls)?;

        // See: https://wiki.wireshark.org/TLS#tls-decryption
        if std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME).is_ok() {
            config.key_log = Arc::new(KeyLogFile::new());
        }

        Ok(config)
    }
}

struct LazyFile {
    path: PathBuf,
    file: Option<File>,
}

impl LazyFile {
    fn lazy_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.file.is_none() {
            self.file = Some(File::open(&self.path)?);
        }

        self.file.as_mut().unwrap().read(buf)
    }
}

impl Read for LazyFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.lazy_read(buf).map_err(|err| {
            let kind = err.kind();
            io::Error::new(kind, format!("error reading file ({:?}): {}", self.path.display(), err))
        })
    }
}

impl Transport for TlsStream {
    fn remote_addr(&self) -> Option<SocketAddr> {
        match self.state {
            State::Handshaking(_) => None,
            State::Streaming(ref stream) => Some(stream.get_ref().0.remote_addr()),
        }
    }
}

enum State {
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

// tokio_rustls::server::TlsStream doesn't expose constructor methods,
// so we have to TlsAcceptor::accept and handshake to have access to it
// TlsStream implements AsyncRead/AsyncWrite handshaking tokio_rustls::Accept first
pub(crate) struct TlsStream {
    state: State,
}

impl TlsStream {
    fn new(stream: AddrStream, config: Arc<ServerConfig>) -> TlsStream {
        let accept = tokio_rustls::TlsAcceptor::from(config).accept(stream);
        TlsStream {
            state: State::Handshaking(accept),
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_read(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_write(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(crate) struct TlsAcceptor {
    config: Arc<ServerConfig>,
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub(crate) fn new(config: ServerConfig, incoming: AddrIncoming) -> TlsAcceptor {
        TlsAcceptor {
            config: Arc::new(config),
            incoming,
        }
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = io::Error;

    fn poll_accept(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.config.clone())))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}
