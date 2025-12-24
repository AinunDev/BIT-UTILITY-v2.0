BIT-UTILITY v2.0 is a Python-based command-line tool for Bitcoin key and address operations. It supports conversion and verification of private keys (hex and WIF), public keys (compressed and uncompressed), and Bitcoin addresses across Legacy (P2PKH), Nested SegWit (P2SH-P2WPKH), and Native SegWit (Bech32) formats.

The utility implements core Bitcoin cryptography using the secp256k1 curve, including SHA-256, RIPEMD-160, Base58Check, and Bech32 encoding. It also provides address validation, HASH160 generation, limited public key lookup for legacy addresses, and deterministic brain-wallet derivation.

Designed for educational, auditing, and offline analysis purposes, BIT-UTILITY focuses on cryptographic transformations and validation only and does not create or sign transactions.
