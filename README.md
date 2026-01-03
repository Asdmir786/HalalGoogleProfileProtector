# Halal Google Profile Protector (HGP)

Modern desktop application to secure your Chrome profiles and custom folders.

- **Strong Security**: Password-based encryption using **Argon2id** (KDF) and **AES-256-GCM** (Authenticated Encryption).
- **Multi-Profile Support**: Automatically discovers and manages multiple Chrome profiles (`Default`, `Profile 1`, etc.).
- **Batch Operations**: Encrypt or decrypt multiple profiles at once with a single password prompt.
- **Modern UI**: Built with PySide6 (Qt) featuring a background worker to keep the interface smooth.
- **Standalone**: Packaged as a high-performance Windows `.exe` via Nuitka.

## Requirements
- Python 3.11+ (Python 3.12 recommended for building)
- [uv](https://github.com/astral-sh/uv) (high-performance Python package manager)
- Windows 10/11

## Quick Start (Development)
```powershell
# Install dependencies (including dev tools)
uv sync --extra dev

# Run the application
uv run halal-gpp
```

## Build Executable
We use Nuitka for a fast, single-file executable.
```powershell
uv run python build.py
```

## Notes
- **Privacy**: No data ever leaves your machine. Encryption is entirely local.
- **Safety**: Always close Chrome before running encryption or decryption to avoid file locks.
- **Password**: Your password is the ONLY key. There is no "recovery" if you lose it.
