# Halal Google Profile Protector (HGP)

Desktop app to encrypt/decrypt your Chrome profile at:
C:\\Users\\3D\\AppData\\Local\\Google\\Chrome\\User Data\\Default

- Password-based encryption (Argon2id + AES-256-GCM)
- Single encrypted archive: `Default.hgp`
- GUI built with PySide6
- Packaged as a Windows .exe (via Nuitka)

## Requirements
- Python 3.11+
- uv (package manager)
- Windows 10/11

## Quick start (with uv)
```
uv sync
uv run halal-gpp
```

## Build .exe (Nuitka)
```
uv run python -m nuitka ^
  --onefile --standalone --lto=yes ^
  --plugin-enable=pyside6 ^
  --windows-console=no ^
  src\halal_gpp\app.py
```

## Notes
- Keep your password safe. Losing it means losing the ability to decrypt.
- Close Chrome before encrypting or decrypting.
