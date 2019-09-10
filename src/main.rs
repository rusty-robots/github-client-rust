use futures::{future, Future, Stream};
use gotham::handler::{HandlerFuture, IntoHandlerError};
use gotham::helpers::http::response::create_empty_response;
use gotham::router::builder::{build_simple_router, DefineSingleRoute, DrawRoutes};
use gotham::router::Router;
use gotham::state::{FromState, State};
use hyper::{Body, HeaderMap, Method, Response, StatusCode, Uri, Version};

use futures::future::{lazy, poll_fn};
use tokio_threadpool::{blocking, ThreadPool};

use serde_json;

use std::env;
use std::option::Option;

use openssl::hash::MessageDigest;
use openssl::memcmp;
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

/// Show the GET request components by printing them.
fn get_handler(state: State) -> (State, Response<Body>) {
    print_request_elements(&state);
    let res = create_empty_response(&state, StatusCode::OK);

    (state, res)
}

fn home(state: State) -> (State, Response<Body>) {
    get_handler(state)
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
fn verify_payload_signature(signature: &Option<String>, secret: &String, body: &String) -> bool {
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

            println!("signature: sha1={:?}", sighex);
            println!("bytes: {:?}", sigbytes);
            println!("hmac is: {:?}", hmac);
            //            println!("hmac len: {}, sig len: {}", hmac.len(), sigbytes.len());

            let valid = memcmp::eq(&hmac, &sigbytes);
            println!("validity is: {:?}", valid);
            valid
        }
        None => false,
    }
}

/// Installation Integration
/// Installation
///
/// When creating a new push with branch we expect:
/// * create ref: branch
/// * push to branch
/// * check_run for push
///  Process:
/// get JWT
/// get Install token
/// create check-run
fn handle_push_event(
    push: octokit::PushPayload,
) -> impl Future<Item = octokit::CheckRun, Error = Box<dyn std::error::Error + 'static>> {
    future::ok(1)
        .and_then(|_| {
            let key_path = env::var("GITHUB_PRIVATE_KEY_PATH")
                .expect("GITHUB_PRIVATE_KEY_PATH is required but not set.");
            let app_id = env::var("GITHUB_APP_ID").expect("GITHUB_APP_ID is required but not set.");
            println!("calling create jwt");
            future::ok(octokit::create_jwt(&key_path, &app_id).unwrap())
        })
        .and_then(|jwt| {
            let installation_id = 1839142;
            println!("calling create installation token");
            future::ok(octokit::create_installation_token(jwt, installation_id).unwrap())
        })
        .and_then(|token| {
            let nwo = env::var("PLAYGROUND_NWO").expect("PLAYGROUND_NWO is required but not set.");
            println!("calling create check run");
            future::ok(octokit::create_check_run(&token, &nwo, push.after).unwrap())
        })
}

fn webhook_handler(mut state: State) -> Box<HandlerFuture> {
    print_request_elements(&state);
    //  may outlive borrowed value `event_type`, ...
    //  let event_type = extract_event_type(&state).expect("Unable to extract event type (X-EVENT-TYPE)");
    //  let secret = env::var("GITHUB_WEBHOOK_SECRET")
    //  let signature = get_payload_signature(&state);

    let f = Body::take_from(&mut state)
        .concat2()
        .then(|full_body| match full_body {
            Ok(valid_body) => {
                // parse body
                let secret = env::var("GITHUB_WEBHOOK_SECRET")
                    .expect("GITHUB_WEBHOOK_SECRET is required but not set.");
                let signature = get_payload_signature(&state);
                let body_content = String::from_utf8(valid_body.to_vec()).unwrap();

                // validate  signature
                let signature_is_valid =
                    verify_payload_signature(&signature, &secret, &body_content);
                if signature_is_valid {
                    println!("YESS, signature is valid");
                } else {
                    println!("BOO, signature is NOT valid");
                }
                // do stuff
                let event_type = extract_event_type(&state)
                    .expect("Unable to extract event type (X-EVENT-TYPE)");
                println!("Event type is: {} ", event_type);
                match event_type.as_str() {
                    "installation" => {
                        println!("{}", body_content);
                        println!("Processing installation webhook");
                        let data: octokit::InstallationPayload =
                            serde_json::from_str(body_content.as_str()).unwrap();

                        println!("parsed data: {:?}", data);
                    }
                    "push" => {
                        //                        println!("{}", body_content);
                        let pool = ThreadPool::new();
                        pool.spawn(lazy(move || {
                            poll_fn(move || {
                                blocking(|| {
                                    println!("Processing push webhook");
                                    let push: octokit::PushPayload =
                                        serde_json::from_str(body_content.as_str()).unwrap();
                                    println!("parsed data: {:?}", push);
                                    println!("before {}, after: {}", push.before, push.after);

                                    let check_run = handle_push_event(push).wait();
                                })
                                .map_err(|_| panic!("the threadpool shut down"))
                            })
                        }));
                        // Wait for the task we just spawned to complete.
                        println!("Waiting for shutdown");
                        pool.shutdown_on_idle().wait().unwrap();
                        println!("Done shutting down");
                    }
                    "check_suite" => {
                        println!("Ignoring check suite event");
                    }
                    _ => {
                        println!("Unknown event type: {}", event_type);
                        println!("{}", body_content);
                    }
                }

                // move data to background job

                // respond
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
/// /github/setup?installation_id=1841686&setup_action=install
fn setup(state: State) -> (State, &'static str) {
    // TODO extract installation_id and setup_action from query parameters
    print_request_elements(&state);
    // redirect back to github installation???
    // https://docs.rs/gotham/0.4.0/gotham/helpers/http/response/fn.create_temporary_redirect.html
    // let resp = create_temporary_redirect(&state, "/quick-detour");
    //    (state, resp)
    (state, HELLO_WORLD)
}
fn router() -> Router {
    build_simple_router(|route| {
        route.get_or_head("/home").to(home);

        route.scope("/github", |route| {
            route.post("/events").to(webhook_handler);
            route.post("/auth/callback").to(auth_callback);
            route.get("/setup").to(setup);
        });
    })
}

/// Start a server and use a `Router` to dispatch requests
pub fn main() {
    let addr = "127.0.0.1:7878";
    println!("Listening for requests at http://{}", addr);
    gotham::start(addr, router())
}
