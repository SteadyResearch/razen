#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(
        razen_engine::application::proof_entry::run(std::env::args_os().skip(1).collect()).await,
    )
}
