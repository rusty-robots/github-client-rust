extern crate probot;

fn main() -> std::io::Result<()> {
    return probot::start();
    // I guess we might also use the builder pattern?
    // Probot::new().start()
}
