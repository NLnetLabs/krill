extern crate rpubd;

#[macro_use] extern crate lazy_static;

use rpubd::config::Config;
use rpubd::server;
use rpubd::provisioning::publisher_list::PublisherList;

lazy_static! {
    static ref CONFIG: Config = {
        match Config::create() {
            Ok(c)  => c,
            Err(e) => {
                eprintln!("{}", e);
                ::std::process::exit(1);
            }
        }
    };
}

fn main() {

    let mut list = match PublisherList::new(
        CONFIG.data_dir(),
        CONFIG.rsync_base()) {
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        },
        Ok(list) => list
    };

    list.sync_from_dir(
        CONFIG.pub_xml_dir().clone(),
        "start up syncer".to_string()
    ).unwrap();

    server::serve(&CONFIG.socket_addr(), list);
}
