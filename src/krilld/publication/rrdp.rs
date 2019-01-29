//use rpki::uri;
//use crate::api::requests;
//use crate::storage::keystore;
//
//
//fn uri(
//    server_uri: &uri::Http,
//    session_id: &str,
//    serial: &usize,
//    filename: &str
//) -> uri::Http {
//    let uri = format!(
//        "{}rrdp/{}/{}/{}",
//        server_uri.to_string(),
//        session_id,
//        serial,
//        filename
//    );
//    uri::Http::from_string(uri).unwrap()
//}
//
////------------ Snapshot ----------------------------------------------------
//
//#[derive(Clone, Debug, Deserialize, Serialize)]
//pub struct Snapshot {
//    session_id: String,
//    serial: usize,
//    files: Vec<requests::Publish>
//}
//
//impl Snapshot {
//    pub fn key(&self) -> keystore::Key {
//        keystore::Key::from_str(
//            &format!("snapshot-{}-{}", &self.session_id, &self.serial)
//        )
//    }
//
//    pub fn json_uri(&self, server_uri: &uri::Http) -> uri::Http {
//        uri(server_uri, &self.session_id, &self.serial, "snapshot.json")
//    }
//
//    pub fn xml_uri(&self, server_uri: &uri::Http) -> uri::Http {
//        uri(server_uri, &self.session_id, &self.serial, "snapshot.xml")
//    }
//}
//
//#[derive(Clone, Debug, Deserialize, Serialize)]
//pub struct Delta {
//    session_id: String,
//    serial: usize,
//    delta: requests::PublishDelta
//}
//
//impl Delta {
//    pub fn key(&self) -> keystore::Key {
//        keystore::Key::from_str(
//            &format!("snapshot-{}-{}", &self.session_id, &self.serial)
//        )
//    }
//
//    pub fn json_uri(&self, server_uri: &uri::Http) -> uri::Http {
//        uri(server_uri, &self.session_id, &self.serial, "snapshot.json")
//    }
//
//    pub fn xml_uri(&self, server_uri: &uri::Http) -> uri::Http {
//        uri(server_uri, &self.session_id, &self.serial, "snapshot.xml")
//    }
//}
//
////------------ Notification  -------------------------------------------------
//
//
//#[derive(Clone, Debug, Deserialize, Serialize)]
//pub struct FileRef {
//    serial: usize,
//    size: usize,
//    xml_uri: uri::Http,
//    json_uri: uri::Http,
//}
//
//#[derive(Clone, Debug, Deserialize, Serialize)]
//pub struct Notification {
//    session_id: String,
//    current_serial: usize,
//    snapshot: FileRef,
//    deltas: Vec<FileRef>
//}
//
//impl Notification {
//    pub fn key(&self) -> keystore::Key {
//        keystore::Key::from_str("notification")
//    }
//
//    pub fn json_uri(&self, server_uri: &uri::Http) -> uri::Http {
//        let uri = format!("{}rrdp/notification.json", server_uri.to_string());
//        uri::Http::from_string(uri).unwrap()
//    }
//
//    pub fn xml_uri(&self, server_uri: &uri::Http) -> uri::Http {
//        let uri = format!("{}rrdp/notification.xml", server_uri.to_string());
//        uri::Http::from_string(uri).unwrap()
//    }
//}
