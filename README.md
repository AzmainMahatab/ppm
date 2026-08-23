# Portable Package Manager (`ppm`)

A lightweight, zero-dependency, single-binary portable application runner and virtualization package manager for Windows.

## Quick Start (End Users)

1. Download or copy **`ppm.exe`** into any directory (or the root of a portable USB flash drive).
2. Open a terminal in that folder and run:
   ```bash
   ppm.exe init
   ```
3. Install all configured applications:
   ```bash
   ppm.exe install all
   ```
4. Run your applications:
   * Double-click `antigravity.bat` (or run `ppm.exe run antigravity`)
   * Double-click `antigravity-manager.bat` (or run `ppm.exe run antigravity-manager`)

---

## Developer Documentation

For complete architectural details, Windows NT virtualization mechanics, and path invariants, see [ARCHITECTURE.md](ARCHITECTURE.md).

### Building from Source (100% Native Cargo)

```bash
# Clone the repository (with submodules)
git clone --recursive <repo-url>

# Compile release binary
cargo build --release
```

**Output Artifact**: `target/release/ppm.exe` (~4 MB single binary with all runtime components embedded).
