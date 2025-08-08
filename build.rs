use std::env;
use std::fs;

fn main() {
    // Only increment version in local release builds, not CI
    if env::var("PROFILE").unwrap_or_default() == "release" 
        && env::var("CI").is_err()  // Skip auto-increment in CI environment
        && env::var("GITHUB_ACTIONS").is_err() { // Skip auto-increment in GitHub Actions
        increment_version();
    }
}

fn increment_version() {
    let cargo_toml_path = "Cargo.toml";
    
    // Read current Cargo.toml
    let contents = match fs::read_to_string(cargo_toml_path) {
        Ok(contents) => contents,
        Err(_) => return, // Skip if can't read file
    };
    
    // Find and increment version
    let mut lines: Vec<String> = contents.lines().map(|s| s.to_string()).collect();
    for line in &mut lines {
        if line.starts_with("version = ") {
            if let Some(version_str) = extract_version(line) {
                if let Some(new_version) = increment_patch_version(&version_str) {
                    *line = format!("version = \"{}\"", new_version);
                    break;
                }
            }
        }
    }
    
    // Write back to Cargo.toml
    let new_contents = lines.join("\n");
    let _ = fs::write(cargo_toml_path, new_contents);
}

fn extract_version(line: &str) -> Option<String> {
    // Extract version from line like: version = "0.1.0"
    let start = line.find('"')? + 1;
    let end = line.rfind('"')?;
    if start < end {
        Some(line[start..end].to_string())
    } else {
        None
    }
}

fn increment_patch_version(version: &str) -> Option<String> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() == 3 {
        let major: u32 = parts[0].parse().ok()?;
        let minor: u32 = parts[1].parse().ok()?;
        let patch: u32 = parts[2].parse().ok()?;
        
        Some(format!("{}.{}.{}", major, minor, patch + 1))
    } else {
        None
    }
}