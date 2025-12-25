# BIT-UTILITY v2.0

BIT-UTILITY v2.0 is a **Python-based command-line tool** for Bitcoin key and address operations. It supports conversion, verification, and derivation of private keys, public keys, and Bitcoin addresses across **Legacy (P2PKH)**, **Nested SegWit (P2SH-P2WPKH)**, and **Native SegWit (Bech32)** formats.

---

## Features

* **Private Key Operations**: HEX ↔ WIF (compressed/uncompressed), verification
* **Public Key Operations**: Compress/uncompress, derive addresses, RIPEMD160 hash, verification
* **Bitcoin Address Operations**: Verify addresses, HASH160, extract public key (legacy only)
* **Brain Wallet Support**: Deterministic derivation from passphrase → HEX, WIF, addresses, RMD160 hashes
* **Core Bitcoin Cryptography**: secp256k1 curve, SHA-256, RIPEMD-160, Base58Check, Bech32
* **Offline & Educational**: Focused on cryptographic transformations and validation only

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/AinunDev/BIT-UTILITY.git
cd BIT-UTILITY-v2.0
pip install -r requirements.txt
python BIT-UTILITY-v2.0.py
```

### Optional Standalone Executable

Compile to a standalone `.exe` using **Nuitka**:

```bash
nuitka --standalone --onefile BIT-UTILITY-v2.0.py
```

> You can run the executable without Python or dependencies.
> Some antivirus programs may flag it due to compilation; this is a false positive.
> The **source code is included** for verification or recompilation.

---

## Supported Operations

### WIF Operations

* WIF → HEX
* WIF → Compressed/Uncompressed Public Key
* WIF → Addresses
* WIF Compressed ↔ Uncompressed
* Verify WIF

### HEX Operations

* HEX → WIF (Compressed/Uncompressed)
* HEX → Compressed/Uncompressed Public Key
* HEX → Addresses
* Verify HEX Private Key

### Public Key Operations

* Compress ↔ Uncompress
* Public Key → Addresses
* Public Key → RMD160 Hash
* Verify Public Key

### Address Operations

* Address → Public Key (legacy only, online)
* Address → RMD160 Hash
* Verify Address
* Check Address Type (Compressed/Uncompressed)

### Brain Wallet Operations

* Passphrase → HEX
* Passphrase → WIF (Compressed/Uncompressed)
* Passphrase → Addresses
* Passphrase → RMD160 Hashes

---

## Usage

Run the program:

```bash
python BIT-UTILITY-v2.0.py
```

Follow the **interactive menu** to select operations. Outputs are displayed clearly in the terminal.

---

## Disclaimer

This project is **for educational, auditing, and offline analysis purposes only**.

* The tool **does not** create or sign Bitcoin transactions.
* You are responsible for complying with all applicable laws and regulations.
* The author is **not liable** for misuse, data loss, or legal consequences.

Do you want me to create that?
