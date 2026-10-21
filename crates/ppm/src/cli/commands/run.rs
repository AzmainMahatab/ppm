use std::path::Path;

use ppm::engine;

/// Launches the application and returns its exit code, which `ppm` itself exits with.
pub(crate) fn run(root: &Path, app: &str, args: &[String]) -> anyhow::Result<i32> {
    engine::runner::run_app(root, app, args)
}
