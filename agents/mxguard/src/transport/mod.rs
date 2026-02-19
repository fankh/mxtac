//! Transport layer for shipping OCSF events to the MxTac backend.

pub mod http;

pub use http::HttpTransport;
