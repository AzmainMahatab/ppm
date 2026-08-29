use std::path::Path;

use anyhow::Context;
use ppm::core::config::AppManifests;

pub(crate) fn run(root: &Path) -> anyhow::Result<()> {
    let schema = schemars::schema_for!(AppManifests);
    let schema_json = serde_json::to_string_pretty(&schema)?;

    let schema_targets = [
        root.join(".ppm").join("apps.schema.json"),
        root.join("manifests").join("apps.schema.json"),
    ];
    for target in &schema_targets {
        std::fs::write(target, &schema_json)
            .with_context(|| format!("Failed to write '{}'", target.display()))?;
    }

    println!(
        "✓ JSON Schema generated at '{}' and '{}'",
        schema_targets[0].display(),
        schema_targets[1].display()
    );
    Ok(())
}
