use crate::{
    error::{Error, Result},
    validation, worker,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};
use tokio::{process::Command, sync::Mutex};

const OPERATIONS: [&str; 18] = [
    "base64-encode",
    "base64-decode",
    "base64url-encode",
    "base64url-decode",
    "hex-encode",
    "hex-decode",
    "url-encode",
    "url-decode",
    "base36-encode",
    "base36-decode",
    "gzip-compress",
    "gzip-decompress",
    "zlib-compress",
    "zlib-decompress",
    "deflate-compress",
    "deflate-decompress",
    "json-pretty",
    "json-minify",
];
pub struct Decoder {
    path: PathBuf,
    lock: Mutex<()>,
}
impl Decoder {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }
    pub fn state(&self) -> Value {
        json!({"protocol_version":1,"available":worker::executable(&self.path),"busy":self.lock.try_lock().is_err(),"limits":{"input_bytes":1048576,"output_bytes":1048576,"pipeline_steps":16,"retained_bytes":4194304,"jwt_bytes":65536,"secret_bytes":4096,"json_depth":64,"json_tokens":100000,"timeout_ms":2000,"operations":OPERATIONS,"jwt_algorithms":["HS256","HS384","HS512","none"]}})
    }
    pub async fn action(&self, value: &Value) -> Result<Value> {
        validation::schema("DecoderAction", value, 400)?;
        let action = value["action"].as_str().unwrap_or("");
        let mut args = Vec::<String>::new();
        let input: Vec<u8>;
        match action {
            "transform" => {
                let op =
                    validation::text(&value["operation"], "Decoder operation", 64, false, false)?;
                if !OPERATIONS.contains(&op) {
                    return Err(Error::bad("Decoder transform is not allowlisted"));
                }
                let encoded =
                    validation::text(&value["input_base64"], "Decoder input", 1398108, true, true)?;
                input = STANDARD
                    .decode(encoded)
                    .map_err(|_| Error::bad("Decoder input must be canonical Base64"))?;
                if input.len() > 1048576 {
                    return Err(Error::bad("Decoder input exceeds 1 MiB"));
                }
                args.extend(["transform".into(), op.into()]);
            }
            "jwt_inspect" => {
                args.push("jwt-inspect".into());
                input = validation::text(&value["token"], "JWT", 65536, true, true)?
                    .as_bytes()
                    .to_vec();
            }
            "jwt_verify" => {
                args.push("jwt-verify".into());
                input = frame(&[
                    validation::text(&value["token"], "JWT", 65536, true, true)?.as_bytes(),
                    validation::text(&value["secret"], "JWT HMAC secret", 4096, false, true)?
                        .as_bytes(),
                ]);
            }
            "jwt_create" => {
                let alg = validation::text(&value["algorithm"], "JWT algorithm", 16, false, false)?;
                let secret =
                    validation::text(&value["secret"], "JWT HMAC secret", 4096, true, true)?;
                if alg == "none" {
                    if value["allow_unsigned_confirmed"] != true || !secret.is_empty() {
                        return Err(Error::bad(
                            "Unsigned JWT creation requires confirmation and an empty secret",
                        ));
                    }
                } else if !["HS256", "HS384", "HS512"].contains(&alg) || secret.is_empty() {
                    return Err(Error::bad(
                        "Signed JWT creation requires a supported algorithm and HMAC secret",
                    ));
                }
                let expiry = if value["expires_in_seconds"].is_null() {
                    "none".into()
                } else {
                    (validation::now_ms() / 1000
                        + validation::integer(
                            &value["expires_in_seconds"],
                            "JWT expiry",
                            1,
                            604800,
                        )?)
                    .to_string()
                };
                args.extend(["jwt-create".into(), alg.into(), expiry]);
                input = frame(&[
                    validation::text(&value["payload_json"], "JWT payload", 57344, true, true)?
                        .as_bytes(),
                    secret.as_bytes(),
                ]);
            }
            _ => return Err(Error::bad("Decoder action is unsupported")),
        }
        if !worker::executable(&self.path) {
            return Err(Error::new(
                503,
                "The native decoder executable is unavailable",
            ));
        }
        let _guard = tokio::time::timeout(Duration::from_secs(2), self.lock.lock())
            .await
            .map_err(|_| Error::new(408, "The native decoder is busy"))?;
        let output = worker::run(
            Command::new(&self.path)
                .args(args)
                .env_clear()
                .env("LC_ALL", "C")
                .env("PATH", "/usr/bin:/bin"),
            &input,
            if action == "transform" {
                1048576
            } else {
                262144
            },
            Duration::from_secs(2),
        )
        .await?;
        if !output.success {
            return Err(Error::new(
                if output.exit_code == Some(3) || action != "transform" {
                    422
                } else {
                    400
                },
                if output.stderr.is_empty() {
                    "Native decoder rejected the operation".into()
                } else {
                    validation::truncate(String::from_utf8_lossy(&output.stderr).trim(), 4096)
                },
            ));
        }
        if action == "transform" {
            Ok(
                json!({"protocol_version":1,"ok":true,"operation_id":value["operation_id"],"operation":value["operation"],"input_bytes":input.len(),"output_bytes":output.bytes.len(),"output_base64":STANDARD.encode(&output.bytes),"utf8_text":std::str::from_utf8(&output.bytes).ok(),"hex_preview":hex::encode(&output.bytes[..output.bytes.len().min(256)]),"preview_truncated":output.bytes.len()>256,"duration_us":output.duration_us}),
            )
        } else {
            let mut value: Value = serde_json::from_slice(&output.bytes)
                .map_err(|_| Error::protocol("Native JWT decoder returned malformed JSON"))?;
            validation::fields(
                &value,
                if action == "jwt_create" {
                    &["protocol_version", "ok", "token", "error"]
                } else {
                    &[
                        "protocol_version",
                        "ok",
                        "algorithm",
                        "signature_status",
                        "header_json",
                        "payload_json",
                        "token_bytes",
                        "signature_bytes",
                        "error",
                    ]
                },
                "Native JWT response",
            )
            .map_err(|e| Error::protocol(e.message))?;
            value["duration_us"] = json!(output.duration_us);
            Ok(value)
        }
    }
}
fn frame(parts: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    for part in parts {
        output.extend_from_slice(&(part.len() as u32).to_be_bytes());
        output.extend_from_slice(part);
    }
    output
}
