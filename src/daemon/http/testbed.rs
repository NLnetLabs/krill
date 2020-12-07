use hyper::Method;

use crate::{constants::ACTOR_TESTBED, commons::api::Handle};
use crate::daemon::ca::{ta_handle, testbed_ca_handle};
use crate::daemon::http::{HttpResponse, Request, RequestPath, RoutingResult};
use crate::daemon::http::server::{
    api_add_pbl,
    api_ca_add_child,
    api_ca_child_remove,
    api_ca_parent_res_xml,
    api_remove_pbl,
    api_repository_response_xml,
    render_ok,
    render_unknown_method,
};

//------------ Support acting as a testbed -------------------------------------
//
// Testbed mode enables Krill to run as an open root of a test RPKI hierarchy
// with web-UI based self-service ability for other RPKI certificate authorities
// to integrate themselves into the test RPKI hierarchy, both as children whose
// resources are delegated from the testbed and as publishers into the testbed
// repository. This feature is very similar to existing web-UI based
// self-service RPKI test hierarchies such as the RIPE NCC RPKI Test Environment
// and the APNIC RPKI Testbed.
//
// Krill can already do this via a combination of use_ta=true and the existing
// Krill API _but_ crucially the other RPKI certificate authorities would need
// to know the Krill API token in order to register themselves with the Krill
// testbed, giving them far too much power over the testbed. Testbed mode
// exposes *open* /testbed/xxx wrapper API endpoints for exchanging the RFC 8183
// XMLs, e.g.:
//
//   /testbed/enabled:    should the web-UI show the testbed UI page?
//   /testbed/children:   <client_request/> in, <parent_response/> out
//   /testbed/publishers: <publisher_request/> in, <repository_response/> out
//
// This feature assumes the existence of a built-in "testbed" CA and publisher
// when testbed mode is enabled.

pub async fn testbed(mut req: Request) -> RoutingResult {
    if !req.path().full().starts_with("/testbed") {
        Err(req) // Not for us
    } else if !req.state().read().await.testbed_enabled() {
         render_unknown_method()
    } else {
        // The testbed is intended to be used without being logged in but
        // anonymous users don't have the necessary rights to manipulate
        // Krill CAs and publishers. Upgrade anonymous users with testbed
        // rights ready for the next call in the chain to the testbed()
        // API call handler functions.
        if req.actor().is_none() {
            req.become_actor(ACTOR_TESTBED.clone()).await;
        }

        let mut path = req.path().clone();
        match path.next() {
            Some("enabled") => testbed_enabled(req).await,
            Some("children") => testbed_children(req, &mut path).await,
            Some("publishers") => testbed_publishers(req, &mut path).await,
            _ => render_unknown_method(),
        }
    }
}

// Is the testbed feature enabled or not? used by the web-UI to conditionally
// enable the testbed web-UI.
async fn testbed_enabled(req: Request) -> RoutingResult {
    match *req.method() {
        Method::GET => render_ok(),
        _ => render_unknown_method(),
    }
}

// Open (token-less) addition/removal of child CAs under the testbed CA.
// Note: Anyone can request any resources irrespective of the resources they
// have the rights to in the real global RPKI hierarchy and anyone can
// unregister any child CA even if not "owned" by them.
async fn testbed_children(req: Request, path: &mut RequestPath) -> RoutingResult {
    match (req.method().clone(), path.path_arg()) {
        (Method::GET, Some(child)) => match path.next() {
            Some("parent_response.xml") => api_ca_parent_res_xml(req, testbed_ca_handle(), child).await,
            _ => render_unknown_method(),
        },
        (Method::DELETE, Some(child)) => api_ca_child_remove(req, testbed_ca_handle(), child).await,
        (Method::POST, None) => api_ca_add_child(req, testbed_ca_handle()).await,
        _ => render_unknown_method(),
    }
}

// Open (token-less) addition/removal of publishers to the testbed repository.
// Note: Anyone can become a publisher and anyone can unregister a publisher
// even if not "owned" by them.
async fn testbed_publishers(req: Request, path: &mut RequestPath) -> RoutingResult {
    match (req.method().clone(), path.path_arg()) {
        (Method::GET, Some(publisher)) => match path.next() {
            Some("response.xml") => api_repository_response_xml(req, publisher).await,
            _ => render_unknown_method(),
        },
        (Method::DELETE, Some(publisher)) => testbed_remove_pbl(req, publisher).await,
        (Method::POST, None) => api_add_pbl(req).await,
        _ => render_unknown_method(),
    }
}

// Prevent deletion of the built-in TA and testbed repositories.
async fn testbed_remove_pbl(req: Request, publisher: Handle) -> RoutingResult {
    if publisher == ta_handle() || publisher == testbed_ca_handle() {
        Ok(HttpResponse::forbidden(format!("Publisher '{}' cannot be removed", publisher)))
    } else {
        api_remove_pbl(req, publisher).await
    }
}