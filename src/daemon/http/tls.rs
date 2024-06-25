//! Utitilies for dealing with TLS.

use futures_util::future::Either;
use futures_util::{pin_mut, ready, TryFuture};
use pin_project_lite::pin_project;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{error, fmt, io};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::KeyLogFile;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{Accept, TlsAcceptor};

pub use tokio_rustls::rustls::ServerConfig;

//------------ Constants ----------------------------------------------------

const SSLKEYLOGFILE_ENV_VAR_NAME: &str = "SSLKEYLOGFILE";

//------------ create_server_config -----------------------------------------

/// Creates the TLS server config.
pub fn create_server_config(
    key_path: &Path,
    cert_path: &Path,
) -> Result<ServerConfig, TlsConfigError> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(read_certs(cert_path)?, read_key(key_path)?)
        .map_err(|err| TlsConfigError::other(ErrorKind::Tls, err))?;

    // See: https://wiki.wireshark.org/TLS#tls-decryption
    if std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME).is_ok() {
        config.key_log = Arc::new(KeyLogFile::new());
    }

    Ok(config)
}

/// Reads the certificates from the given PEM file.
fn read_certs(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    rustls_pemfile::certs(&mut io::BufReader::new(File::open(path).map_err(
        |err| TlsConfigError::new(ErrorKind::Cert(path.into()), err),
    )?))
    .collect::<Result<_, _>>()
    .map_err(|err| TlsConfigError::new(ErrorKind::Cert(path.into()), err))
}

/// Reads a private key from the given PEM file.
///
/// The key may be a PKCS#1 RSA private key, a PKCS#8 private key, or a
/// SEC1 encoded EC private key. All other PEM items are ignored.
///
/// Errors out if opening or reading the file fails or if there isn’t exactly
/// one recognized private key in the file.
fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsConfigError> {
    use rustls_pemfile::Item::*;

    let mut key_file =
        io::BufReader::new(File::open(path).map_err(|err| {
            TlsConfigError::new(ErrorKind::Key(path.into()), err)
        })?);

    let mut key = None;

    while let Some(item) = rustls_pemfile::read_one(&mut key_file).transpose()
    {
        let item = item.map_err(|err| {
            TlsConfigError::new(ErrorKind::Key(path.into()), err)
        })?;

        let bits = match item {
            Pkcs1Key(bits) => bits.into(),
            Pkcs8Key(bits) => bits.into(),
            Sec1Key(bits) => bits.into(),
            _ => continue,
        };
        if key.is_some() {
            return Err(TlsConfigError::other(
                ErrorKind::Key(path.into()),
                "file contains multiple keys",
            ));
        }
        key = Some(bits)
    }

    key.ok_or_else(|| {
        TlsConfigError::other(
            ErrorKind::Key(path.into()),
            "file does not contain any usable keys",
        )
    })
}

//------------ TlsTcpStream --------------------------------------------------

pin_project! {
    /// A TLS stream that behaves like a regular TCP stream.
    ///
    /// Specifically, `AsyncRead` and `AsyncWrite` will return `Poll::NotReady`
    /// until the TLS accept machinery has concluded.
    #[project = TlsTcpStreamProj]
    enum TlsTcpStream {
        /// The TLS handshake is going on.
        Accept { #[pin] fut: Accept<TcpStream> },

        /// We have a working TLS stream.
        Stream { #[pin] fut: TlsStream<TcpStream> },

        /// TLS handshake has failed.
        ///
        /// Because hyper still wants to do a clean flush and shutdown, we
        /// need to still work in this state. For read and write, we just
        /// keep returning the clean shutdown indication of zero length
        /// operations.
        Empty,
    }
}

impl TlsTcpStream {
    fn new(sock: TcpStream, tls: &TlsAcceptor) -> Self {
        Self::Accept {
            fut: tls.accept(sock),
        }
    }

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Pin<&mut Self>, io::Error>> {
        match self.as_mut().project() {
            TlsTcpStreamProj::Accept { fut } => {
                match ready!(fut.try_poll(cx)) {
                    Ok(fut) => {
                        self.set(Self::Stream { fut });
                        Poll::Ready(Ok(self))
                    }
                    Err(err) => {
                        self.set(Self::Empty);
                        Poll::Ready(Err(err))
                    }
                }
            }
            _ => Poll::Ready(Ok(self)),
        }
    }
}

impl AsyncRead for TlsTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let mut this = match ready!(self.poll_accept(cx)) {
            Ok(this) => this,
            Err(err) => return Poll::Ready(Err(err)),
        };
        match this.as_mut().project() {
            TlsTcpStreamProj::Stream { fut } => fut.poll_read(cx, buf),
            TlsTcpStreamProj::Empty => Poll::Ready(Ok(())),
            _ => unreachable!(),
        }
    }
}

impl AsyncWrite for TlsTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut this = match ready!(self.poll_accept(cx)) {
            Ok(this) => this,
            Err(err) => return Poll::Ready(Err(err)),
        };
        match this.as_mut().project() {
            TlsTcpStreamProj::Stream { fut } => fut.poll_write(cx, buf),
            TlsTcpStreamProj::Empty => Poll::Ready(Ok(0)),
            _ => unreachable!(),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let mut this = match ready!(self.poll_accept(cx)) {
            Ok(this) => this,
            Err(err) => return Poll::Ready(Err(err)),
        };
        match this.as_mut().project() {
            TlsTcpStreamProj::Stream { fut } => fut.poll_flush(cx),
            TlsTcpStreamProj::Empty => Poll::Ready(Ok(())),
            _ => unreachable!(),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let mut this = match ready!(self.poll_accept(cx)) {
            Ok(this) => this,
            Err(err) => return Poll::Ready(Err(err)),
        };
        match this.as_mut().project() {
            TlsTcpStreamProj::Stream { fut } => fut.poll_shutdown(cx),
            TlsTcpStreamProj::Empty => Poll::Ready(Ok(())),
            _ => unreachable!(),
        }
    }
}

//------------ MaybeTlsTcpStream ---------------------------------------------

/// A TCP stream that may or may not use TLS.
pub struct MaybeTlsTcpStream {
    sock: Either<TcpStream, TlsTcpStream>,
}

impl MaybeTlsTcpStream {
    /// Creates a new stream.
    ///
    /// If `tls` is `Some(_)`, the stream will be a TLS stream, otherwise it
    /// will be a plain TCP stream.
    pub fn new(sock: TcpStream, tls: Option<&TlsAcceptor>) -> Self {
        MaybeTlsTcpStream {
            sock: match tls {
                Some(tls) => Either::Right(TlsTcpStream::new(sock, tls)),
                None => Either::Left(sock),
            },
        }
    }
}

impl AsyncRead for MaybeTlsTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), io::Error>> {
        match self.sock {
            Either::Left(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_read(cx, buf)
            }
            Either::Right(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for MaybeTlsTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.sock {
            Either::Left(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_write(cx, buf)
            }
            Either::Right(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<(), io::Error>> {
        match self.sock {
            Either::Left(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_flush(cx)
            }
            Either::Right(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<(), io::Error>> {
        match self.sock {
            Either::Left(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_shutdown(cx)
            }
            Either::Right(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_shutdown(cx)
            }
        }
    }
}

//------------ TlsConfigError -----------------------------------------------

/// Represents errors that can occur building the TlsConfig
#[derive(Debug)]
pub struct TlsConfigError {
    kind: ErrorKind,
    err: io::Error,
}

#[derive(Clone, Debug)]
enum ErrorKind {
    Key(PathBuf),
    Cert(PathBuf),
    Tls,
}

impl TlsConfigError {
    fn new(kind: ErrorKind, err: io::Error) -> Self {
        Self { kind, err }
    }

    fn other(
        kind: ErrorKind,
        err: impl Into<Box<dyn error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            kind,
            err: io::Error::new(io::ErrorKind::Other, err),
        }
    }
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Key(ref path) => {
                write!(
                    f,
                    "Error in TLS key file {}: {}",
                    path.display(),
                    self.err
                )
            }
            ErrorKind::Cert(ref path) => {
                write!(
                    f,
                    "Error in TLS certificate file {}: {}",
                    path.display(),
                    self.err
                )
            }
            ErrorKind::Tls => {
                write!(f, "Error in TLS configuration: {}", self.err)
            }
        }
    }
}

impl error::Error for TlsConfigError {}
