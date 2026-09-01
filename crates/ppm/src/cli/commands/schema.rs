use std::path::Path;

use ppm::core::schema::write_schema_artifacts;

pub(crate) fn run(root: &Path) -> anyhow::Result<()> {
    let written = write_schema_artifacts(root)?;

    if written.is_empty() {
        anyhow::bail!(
            "No schema target directory exists under '{}'. Run 'ppm init' first.",
            root.display()
        );
    }

    println!("✓ JSON Schema generated at:");
    for target in written {
        println!("  • {}", target.display());
    }
    Ok(())
}
