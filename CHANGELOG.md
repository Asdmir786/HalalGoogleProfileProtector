# Changelog

All notable changes to the **Halal Google Profile Protector** project will be documented in this file.

## [2.0.1] - 2025-12-13
### 🐛 Fixes
- Prevented UI freezing during batch encrypt/decrypt by moving work to a background thread.
- Added overwrite/skip prompt when decrypting into existing profile folders.
- Improved `.hgp` archive path handling and conflict checks for batch operations.

### 🛠 Chore
- Bumped project version to 2.0.1 in `pyproject.toml`.

---

## [2.0.0] - 2025-12-12
### 🚀 Features
- **Multi-Profile Support**: Completely replaced single-path input with a scrollable **Checklist UI** for managing multiple profiles.
- **Batch Operations**: 
  - **Encrypt Selected**: Encrypts multiple folders in sequence (single password prompt).
  - **Decrypt Selected**: Decrypts multiple archives in sequence.
- **Auto-Discovery**: Automatically scans `User Data` for `Default`, `Profile X` folders and `.hgp` archives.
- **Smart UI**: 
  - Added "Select All", "Deselect All", "Refresh" buttons.
  - "Browse" now adds custom external folders to the list.
  - Encryption skips existing archives; Decryption skips non-archives.

### 🛠 Chore
- Bumped project version to 2.0.0 in `pyproject.toml` and `__version__`.

---

## [1.1.0] - 2025-12-12
### 📦 Build
- **Nuitka Builder**: Added `build.py` script for creating standalone executables using Nuitka (replaces PyInstaller).
- Updated project version to 1.1.0 in `pyproject.toml`.
- Added build artifacts (`.build`, `.dist`, `.onefile-build`) to `.gitignore`.

---

## [1.0.0] - 2025-12-09
### 🚀 Features
- **GUI**: Initial PySide6 scaffold with "Browse" functionality.
- **App**: Fully wired Encrypt/Decrypt flows with progress bars and logs.
- **Security**: AES-256-GCM + Argon2id encryption engine.
- **Workflow**:
  - Automatically delete the `Default` profile folder after successful encryption.
  - Allow Decrypt even if the original folder is missing (restores from `Default.hgp`).
  - Prompt to delete `Default.hgp` after successful restore.
- **Metrics**: Log elapsed time and archive size (MiB) upon completion.
- **UI Polish**:
  - Show app version (v1.0.0) in window title.
  - Password dialog "Show password" toggle fixes.

### 🐛 Fixes
- **Ops**: Removed invalid `zstandard.bytes_view` usage.
- **Crypto**: Switched to Header MAC + AES-GCM tag verification (removed fragile Argon2 verify pre-check).

### ⚠ Breaking Changes
- **Destructive Encryption**: Encrypt flow now deletes the source folder by default upon success.

### ⚙ Chore
- Init project with `uv` and git.
- Lock dependencies in `uv.lock`.
- Bump version to 1.0.0.

