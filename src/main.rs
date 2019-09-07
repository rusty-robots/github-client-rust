
use gotham::router::Router;
use gotham::router::builder::*;
use gotham::state::State;

const HELLO_WORLD: &'static str = "Hello World!";

/// We've simply implemented the `Handler` trait, for functions that match the signature used here,
/// within Gotham itself.
pub fn say_hello(state: State) -> (State, &'static str) {
    (state, HELLO_WORLD)
    }
fn home(state: State) -> (State, &'static str) {

    (state, HELLO_WORLD)
}

fn webhooks(state: State) -> (State, &'static str) {
    (state, HELLO_WORLD)

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
            route.post("/events").to(webhooks);
            route
                .post("/auth/callback")
                .to(auth_callback);
            route
                .post("/setup")
                .to(setup);
        });
    })
}

/// Start a server and use a `Router` to dispatch requests
pub fn main() {
    let addr = "127.0.0.1:7878";
    println!("Listening for requests at http://{}", addr);
    gotham::start(addr, router())
}
