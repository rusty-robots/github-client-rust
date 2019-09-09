use futures::{future, Future, Stream};
use gotham::handler::{HandlerError, HandlerFuture, IntoHandlerError};
use gotham::helpers::http::response::create_empty_response;
use gotham::router::builder::{build_simple_router, DefineSingleRoute, DrawRoutes};
use gotham::router::Router;
use gotham::state::{FromState, State};
use hyper::{Body, HeaderMap, Method, Response, StatusCode, Uri, Version};

use std::env;
use std::option::Option;

//use openssl;
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::PKey;
use openssl::sign::Signer;

const HELLO_WORLD: &'static str = "Hello World!";

/// Extract the main elements of the request except for the `Body`
fn print_request_elements(state: &State) {
    let method = Method::borrow_from(state);
    let uri = Uri::borrow_from(state);
    let http_version = Version::borrow_from(state);
    let headers = HeaderMap::borrow_from(state);
    println!("Method: {:?}", method);
    println!("URI: {:?}", uri);
    println!("HTTP Version: {:?}", http_version);
    println!("Headers: {:?}", headers);
}

/// Extracts the elements of the POST request and prints them
fn post_handler(mut state: State) -> Box<HandlerFuture> {
    print_request_elements(&state);

    let f = Body::take_from(&mut state)
        .concat2()
        .then(|full_body| match full_body {
            Ok(valid_body) => {
                let body_content = String::from_utf8(valid_body.to_vec()).unwrap();
                println!("Body: {}", body_content);
                let res = create_empty_response(&state, StatusCode::OK);
                future::ok((state, res))
            }
            Err(e) => future::err((state, e.into_handler_error())),
        });

    Box::new(f)
}

/// Show the GET request components by printing them.
fn get_handler(state: State) -> (State, Response<Body>) {
    print_request_elements(&state);
    let res = create_empty_response(&state, StatusCode::OK);

    (state, res)
}

fn home(state: State) -> (State, Response<Body>) {
    get_handler(state)
}

enum GithubEvent {
    Integration,
    Installation,
}

enum GithubEventAction {
    Created,
}

// TODO: make this return Result<GithubEvent, HeaderMapErrorThing>
///  Example headers:
///  "x-github-event": "integration_installation",
///  "x-github-delivery": "95765be0-d2e0-11e9-966b-74649f0cda10",
///  "content-type": "application/json",
fn extract_event_type(state: &State) -> Option<String> {
    let headers = HeaderMap::borrow_from(&state);
    headers
        .get("X-GITHUB-EVENT")
        .map(|val| val.to_str().unwrap().to_string())
}

fn get_payload_signature(state: &State) -> Option<String> {
    let headers = HeaderMap::borrow_from(&state);
    headers
        .get("X-HUB-SIGNATURE")
        .map(|val| val.to_str().unwrap().to_string())
}

///  Example signature header
///  "x-hub-signature": "sha1=4b4a1c9a70dc40caf22099fb2d62a283dedd4614"
fn verify_payload_signature(signature: Option<String>, secret: String, body: String) -> bool {
    let secret = secret.as_bytes();
    let body = body.as_bytes();

    match signature {
        Some(sig) => {
            // discard the 'sha1='-prefix
            let sighex = &sig[5..];
            // decode sha1 has hex bytes
            let sigbytes = hex::decode(sighex).expect("Decoding failed");

            // Create a PKey
            let key = openssl::pkey::PKey::hmac(secret).unwrap();

            // Compute the HMAC
            let mut signer = Signer::new(MessageDigest::sha1(), &key).unwrap();
            signer.update(body).unwrap();
            let hmac = signer.sign_to_vec().unwrap();

            println!("signature 1 : {:?}", sig);
            println!("signature 2: {:?}", sighex);
            println!("signature 3: {:?}", sigbytes);
            println!("hmac is: {:?}", hmac);

            println!("hmac len: {}, sig len: {}", hmac.len(), sigbytes.len());

            let valid = memcmp::eq(&hmac, &sigbytes);
            println!("validity is: {:?}", valid);
            valid
        }
        None => false,
    }
}

/// Installation Integration
/// Installation

fn webhook_handler(mut state: State) -> Box<HandlerFuture> {
    let event_type = extract_event_type(&state);
    let signature = get_payload_signature(&state);
    // FIXME placeholders until stuff works
    let secret =
        env::var("GITHUB_WEBHOOK_SECRET").expect("GITHUB_WEBHOOK_SECRET is required but not set.");

    let f = Body::take_from(&mut state)
        .concat2()
        .then(|full_body| match full_body {
            Ok(valid_body) => {
                // parse body
                let body_content = String::from_utf8(valid_body.to_vec()).unwrap();

                // validate  signature
                let signature_is_valid = verify_payload_signature(signature, secret, body_content);
                if signature_is_valid {
                    println!("YESS, signature is valid");
                } else {
                    println!("BOO, signature is NOT valid");
                }
                // do stuff

                // move data to background job

                let res = create_empty_response(&state, StatusCode::OK);
                future::ok((state, res))
            }

            Err(e) => future::err((state, e.into_handler_error())),
        });
    Box::new(f)
}

fn auth_callback(state: State) -> (State, &'static str) {
    (state, HELLO_WORLD)
}
fn setup(state: State) -> (State, &'static str) {
    (state, HELLO_WORLD)
}
fn router() -> Router {
    build_simple_router(|route| {
        route.get_or_head("/home").to(home);

        route.scope("/github", |route| {
            route.post("/events").to(webhook_handler);
            route.post("/auth/callback").to(auth_callback);
            route.post("/setup").to(setup);
        });
    })
}

/// Start a server and use a `Router` to dispatch requests
pub fn main() {
    let addr = "127.0.0.1:7878";
    println!("Listening for requests at http://{}", addr);
    gotham::start(addr, router())
}
