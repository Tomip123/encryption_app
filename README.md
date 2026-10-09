# Rust Encryption App 🦀🔒

A lightweight, high-performance encryption utility and steganography tool built with Rust. This project provides a robust yet simple interface for securing your files and hiding sensitive data within images.

> **Note:** This is a focused, small-scale project designed for efficiency and ease of use.

## ✨ Features

### 🛡️ Secure File Encryption
- **Multiple Algorithms**: Choose between industry-standard ciphers:
  - **AES-256-GCM**: Military-grade encryption.
  - **AES-128-GCM**: Balanced performance and security.
  - **ChaCha20-Poly1305**: High-speed, modern stream cipher.
- **Argon2id Key Derivation**: Uses the winner of the Password Hashing Competition (PHC) to securely derive encryption keys from your passwords, making brute-force attacks significantly harder.
- **Salt & Nonce**: Each encryption operation uses a unique, randomly generated salt and nonce to prevent replay attacks and ensure identical files produce different ciphertexts.

### 🖼️ Image Steganography
- **Hidden Data**: Hide text messages directly within image pixels (PNG format).
- **Extraction**: Easily retrieve hidden messages from processed images.
- **Discreet**: The modifications are nearly invisible to the naked eye.

### 🖥️ Dual Interface
- **Modern GUI**: A clean, responsive interface built with `egui` and `eframe`.
- **Streamlined CLI**: A powerful command-line interface for automation and quick tasks.

---

## 🚀 Getting Started

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)

### Installation
Clone the repository and build the project:
```bash
git clone https://github.com/your-username/encryption_app.git
cd encryption_app
cargo build --release
```

---

## 📖 Usage

### GUI Mode
The default mode provides a user-friendly window for all operations.
```bash
cargo run --release
```

### CLI Mode
The CLI tool allows for quick file encryption/decryption.
```bash
# Usage:
cargo run --bin cli -- <encrypt|decrypt> <algorithm> <file> <password>

# Example: Encrypt a file using AES-256-GCM
cargo run --bin cli -- encrypt aes256gcm secret.txt mypassword123
```
*Supported algorithms: `aes256gcm`, `aes128gcm`, `chacha20poly1305`*

---

## 🛠️ Technical Stack
- **Language**: Rust
- **UI Framework**: [egui](https://github.com/emilk/egui) / [eframe](https://github.com/emilk/egui/tree/master/crates/eframe)
- **Crypto Libraries**: `aes-gcm`, `chacha20poly1305`, `argon2`
- **Image Processing**: `image`
- **File Dialogs**: `rfd`

---

## ⚖️ License
This project is open-source and available under the MIT License.
---

## 🌐 Run it in your browser

The same program also compiles to WebAssembly and runs entirely inside a web page. Nothing is uploaded: the program has no networking code, so files and passwords never leave your device. Choosing a file reads it into memory, and results are offered as a download.

Build the web version (needs Docker, nothing else installed):

```bash
docker buildx build --file Dockerfile.demo --target dist --output type=local,dest=out .
```

`out/` then holds `index.html`, `start.js`, `app.js` and `app_bg.wasm`. Serve it with any static web server that sends `.wasm` files as `application/wasm`. The page loads only its own files, so it also works under a strict Content-Security-Policy (`script-src 'self' 'wasm-unsafe-eval'`).

The **About** tab has a *Run self-test* button that checks all three ciphers, wrong-password and tamper detection, and the image feature on built-in sample data, in your own browser.

### How it is organised

- `src/lib.rs`: the cryptography. `encrypt_bytes` / `decrypt_bytes` and the image functions work on bytes in memory; `encrypt_file` and friends are thin wrappers for the desktop app and the CLI.
- `src/files.rs`: the only code that differs between desktop and browser (picking a file, delivering a result).
- `src/app.rs`, `src/ui/`: the interface, shared by both.
- `cargo test` runs the unit tests.
