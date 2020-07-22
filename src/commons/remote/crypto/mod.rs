mod cms;
pub use self::cms::*;

mod cert;
pub use self::cert::*;

mod error;
pub use self::error::*;

pub fn test_id_certificate() -> IdCert {
    use bytes::Bytes;

    let data = include_bytes!("../../../../test-resources/oob/id_publisher_ta.cer");
    IdCert::decode(Bytes::from_static(data)).unwrap()
}
