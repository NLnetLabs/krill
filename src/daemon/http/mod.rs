use hyper::Body;

pub mod server;
pub mod ssl;
pub mod statics;

//------------ Response ------------------------------------------------------

pub type Response = hyper::Response<Body>;
