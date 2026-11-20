//! Verify, with wimsey's WIMSE response profile, a response that Cred signed
//! (draft-ietf-wimse-http-signature-08 §3.4-3.5).
//!
//!   cred-wimsey-verify-response <exchange.json>
//!
//! exchange.json: { "status": 200, "headers": [[name, value], ...],
//!   "body_b64": "...", "request": { "method", "path", "query" },
//!   "req_nonce": "..." }. The verifying key is the cnf.jwk of the WIT in the
//! response's Workload-Identity-Token header (its own trust is checked
//! separately with `wimsey wit verify`).
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use wimsey_httpsig::{verify, verify_content_digest, HttpExchange, HttpRequest, HttpResponse, VerifyConfig};
use wimsey_jose::Jwk;

fn main() {
    let path = std::env::args().nth(1).expect("usage: cred-wimsey-verify-response <exchange.json>");
    let x: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let headers: Vec<(String, String)> = x["headers"].as_array().unwrap().iter()
        .map(|h| (h[0].as_str().unwrap().to_owned(), h[1].as_str().unwrap().to_owned())).collect();
    let get = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.clone()).unwrap_or_default();
    let body = STANDARD.decode(x["body_b64"].as_str().unwrap()).unwrap();
    let wit = get("workload-identity-token");
    let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(wit.split('.').nth(1).unwrap()).unwrap()).unwrap();
    let jwk: Jwk = serde_json::from_value(claims["cnf"]["jwk"].clone()).unwrap();
    let key = jwk.to_verifying_key().unwrap();
    let request = HttpRequest {
        method: x["request"]["method"].as_str().unwrap().to_owned(),
        authority: String::new(),
        path: x["request"]["path"].as_str().unwrap().to_owned(),
        query: x["request"]["query"].as_str().map(str::to_owned),
        headers: vec![],
    };
    let response = HttpResponse { status: x["status"].as_u64().unwrap() as u16, headers: headers.clone() };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let config = VerifyConfig {
        now: Some(now),
        leeway: 5,
        wimse_response_profile: true,
        expected_req_nonce: Some(x["req_nonce"].as_str().unwrap().to_owned()),
        ..VerifyConfig::default()
    };
    match verify(&HttpExchange { response: &response, request: &request }, &get("signature-input"), &get("signature"), &key, &config) {
        Ok(v) => {
            // Covering content-digest protects the header string; bind the body too.
            if !verify_content_digest(&get("content-digest"), &body) {
                println!("wimsey response-profile verify: REJECTED content-digest does not match the body");
                std::process::exit(1);
            }
            println!("wimsey response-profile verify: OK label={} components={:?}, content-digest matches the body", v.label, v.components.iter().map(|c| c.quoted_id()).collect::<Vec<_>>());
        }
        Err(e) => { println!("wimsey response-profile verify: REJECTED {e}"); std::process::exit(1); }
    }
}
