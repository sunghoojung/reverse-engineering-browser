use serde_json::{Value, json};
use std::io::Cursor;
use tiny_http::{Header, Response, StatusCode};

pub type HttpResponse = Response<Cursor<Vec<u8>>>;

fn header(name: &[u8], value: &[u8]) -> Header {
    Header::from_bytes(name, value).expect("static HTTP header is valid")
}

pub fn json(value: Value, status: u16) -> HttpResponse {
    Response::from_data(serde_json::to_vec(&value).expect("JSON value is serializable"))
        .with_status_code(StatusCode(status))
        .with_header(header(b"Content-Type", b"application/json; charset=utf-8"))
        .with_header(header(b"Cache-Control", b"no-store"))
}

pub fn error(message: impl Into<String>, status: u16) -> HttpResponse {
    json(json!({ "error": message.into() }), status)
}

pub fn bytes(body: Vec<u8>, content_type: &'static [u8]) -> HttpResponse {
    Response::from_data(body)
        .with_header(header(b"Content-Type", content_type))
        .with_header(header(b"Cache-Control", b"no-store"))
        .with_header(header(b"X-Content-Type-Options", b"nosniff"))
}
