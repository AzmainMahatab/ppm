use std::path::Path;

use ppm::engine;

pub(crate) fn run(root: &Path, app: &str, args: &[String]) -> anyhow::Result<()> {
    let code = engine::runner::run_app(root, app, args)?;
    std::process::exit(code);
}
