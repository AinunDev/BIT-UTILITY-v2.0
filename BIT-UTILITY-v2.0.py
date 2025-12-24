#!/usr/bin/env python3
import hashlib
import base58
import binascii
import requests
from ecdsa import SigningKey, SECP256k1
import bech32

# CONSTANTS
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# CORE CRYPTO FUNCTIONS
def sha256(data): return hashlib.sha256(data).digest()
def ripemd160(data): return hashlib.new('ripemd160', data).digest()
def checksum(data): return sha256(sha256(data))[:4]
def base58_check_encode(data): return base58.b58encode(data + checksum(data)).decode()

# ADDRESS GENERATION
def generate_p2pkh(pubkey, compressed=True):
    if compressed and pubkey.startswith(b'\x04'):
        x = pubkey[1:33]
        y = int.from_bytes(pubkey[33:], 'big')
        pubkey = (b'\x02' if y % 2 == 0 else b'\x03') + x
    return base58_check_encode(b'\x00' + ripemd160(sha256(pubkey)))

def generate_p2sh_p2wpkh(pubkey):
    if pubkey.startswith(b'\x04'):
        x = pubkey[1:33]
        y = int.from_bytes(pubkey[33:], 'big')
        pubkey = (b'\x02' if y % 2 == 0 else b'\x03') + x
    script = b'\x00\x14' + ripemd160(sha256(pubkey))
    return base58_check_encode(b'\x05' + ripemd160(sha256(script)))

def generate_bech32(pubkey):
    if pubkey.startswith(b'\x04'):
        x = pubkey[1:33]
        y = int.from_bytes(pubkey[33:], 'big')
        pubkey = (b'\x02' if y % 2 == 0 else b'\x03') + x
    
    pubkey_hash = ripemd160(sha256(pubkey))
    return bech32_encode("bc", 0, pubkey_hash)

def bech32_encode(hrp, witver, witprog):
    return bech32.encode(hrp, witver, witprog)

def bech32_decode(bech):
    try:
        hrp, data = bech32.decode("bc", bech)
        if hrp is None or data is None:
            return None, None
        return hrp, data
    except:
        return None, None

# WIF FUNCTIONS
def hex_to_wif(hex_privkey, compressed=True):
    try:
        payload = b'\x80' + binascii.unhexlify(hex_privkey)
        if compressed: payload += b'\x01'
        return base58_check_encode(payload)
    except:
        return None

def wif_to_hex(wif):
    try:
        decoded = base58.b58decode_check(wif)
        if decoded[0] != 0x80: return None, None, "Invalid WIF prefix"
        compressed = len(decoded) == 34 and decoded[-1] == 1
        hex_key = decoded[1:33].hex()
        return hex_key, compressed, None
    except Exception as e:
        return None, None, f"Invalid WIF format: {str(e)}"

def wif_compress(wif):
    hex_key, compressed, err = wif_to_hex(wif)
    if err or compressed:
        return None, err or "Already compressed"
    return hex_to_wif(hex_key, True), None

def wif_uncompress(wif):
    hex_key, compressed, err = wif_to_hex(wif)
    if err or not compressed:
        return None, err or "Already uncompressed"
    return hex_to_wif(hex_key, False), None

def verify_wif(wif):
    hex_key, compressed, err = wif_to_hex(wif)
    if err:
        return False, None, err
    
    priv_int = int(hex_key, 16)
    if not (1 <= priv_int < SECP256K1_ORDER):
        return False, None, "Private key out of valid range"
    
    return True, "Compressed" if compressed else "Uncompressed", None

def wif_to_addresses(wif):
    hex_key, _, err = wif_to_hex(wif)
    if err:
        return None, err
    return generate_all_from_hex(hex_key)

# HEX FUNCTIONS
def hex_to_pubkey(hex_privkey):
    try:
        sk = SigningKey.from_string(binascii.unhexlify(hex_privkey), curve=SECP256k1)
        uncompressed = b'\x04' + sk.verifying_key.to_string()
        x, y = sk.verifying_key.pubkey.point.x(), sk.verifying_key.pubkey.point.y()
        compressed = (b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(32, 'big')
        return uncompressed, compressed, None
    except Exception as e:
        return None, None, str(e)

def verify_hex_private_key(hex_str):
    hex_str = hex_str.strip().lower().replace("0x", "")
    try:
        priv_int = int(hex_str, 16)
        if 1 <= priv_int < SECP256K1_ORDER:
            return True, "Valid private key"
        else:
            return False, "Private key out of valid range"
    except ValueError:
        return False, "Invalid hex format"

def generate_all_from_hex(hex_key):
    pub_u, pub_c, err = hex_to_pubkey(hex_key)
    if err: return None, err
    return generate_all_addresses(pub_u, pub_c)

# PUBLIC KEY FUNCTIONS
def compress_pubkey(pubkey_hex):
    if pubkey_hex.startswith(('02', '03')): 
        return pubkey_hex
    if not pubkey_hex.startswith('04'):
        return None
    x, y = pubkey_hex[2:66], int(pubkey_hex[66:], 16)
    return ('02' if y % 2 == 0 else '03') + x

def uncompress_pubkey(pubkey_hex):
    if pubkey_hex.startswith('04'): 
        return pubkey_hex
    if not pubkey_hex.startswith(('02', '03')):
        return None
    
    x = int(pubkey_hex[2:], 16)
    y_sq = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    y = pow(y_sq, (SECP256K1_P + 1) // 4, SECP256K1_P)
    
    if (pubkey_hex[0] == '02' and y % 2 != 0) or (pubkey_hex[0] == '03' and y % 2 == 0):
        y = SECP256K1_P - y
    
    return '04' + f"{x:064x}" + f"{y:064x}"

def verify_public_key(pubkey_hex):
    try:
        if pubkey_hex.startswith('04'):
            if len(pubkey_hex) != 130:
                return False, "Uncompressed key must be 130 chars"
            x = int(pubkey_hex[2:66], 16)
            y = int(pubkey_hex[66:], 16)
            left = (y * y) % SECP256K1_P
            right = (x * x * x + 7) % SECP256K1_P
            if left == right:
                return True, "Valid uncompressed public key"
            else:
                return False, "Point not on curve"
        
        elif pubkey_hex.startswith(('02', '03')):
            if len(pubkey_hex) != 66:
                return False, "Compressed key must be 66 chars"
            uncompressed = uncompress_pubkey(pubkey_hex)
            if uncompressed:
                return verify_public_key(uncompressed)
            else:
                return False, "Invalid compressed key"
        
        return False, "Invalid public key format"
    except:
        return False, "Invalid public key"

def pubkey_to_rmd160(pubkey_hex, compressed=True):
    try:
        if compressed and pubkey_hex.startswith('04'):
            pubkey_hex = compress_pubkey(pubkey_hex)
        elif not compressed and pubkey_hex.startswith(('02', '03')):
            pubkey_hex = uncompress_pubkey(pubkey_hex)
        
        if not pubkey_hex:
            return None, "Invalid public key"
            
        pubkey_bytes = binascii.unhexlify(pubkey_hex)
        return ripemd160(sha256(pubkey_bytes)).hex(), None
    except Exception as e:
        return None, str(e)

def process_public_key(pubkey_hex):
    try:
        if pubkey_hex.startswith('04'):
            pub_u = binascii.unhexlify(pubkey_hex)
            pub_c = binascii.unhexlify(compress_pubkey(pubkey_hex))
        elif pubkey_hex.startswith(('02', '03')):
            pub_c = binascii.unhexlify(pubkey_hex)
            pub_u = binascii.unhexlify(uncompress_pubkey(pubkey_hex))
        else:
            return None, "Invalid public key format"
        return generate_all_addresses(pub_u, pub_c)
    except Exception as e:
        return None, str(e)

def generate_all_addresses(pubkey_uncompressed, pubkey_compressed):
    try:
        return {
            'P2PKH (Uncompressed)': generate_p2pkh(pubkey_uncompressed, compressed=False),
            'P2PKH (Compressed)': generate_p2pkh(pubkey_compressed, compressed=True),
            'Bech32 (Native SegWit)': generate_bech32(pubkey_compressed),
            'P2SH-P2WPKH (Nested SegWit)': generate_p2sh_p2wpkh(pubkey_compressed)
        }, None
    except Exception as e:
        return None, str(e)

# ADDRESS FUNCTIONS
def verify_address(address):
    try:
        if address.startswith('1'):
            decoded = base58.b58decode_check(address)
            if decoded[0] == 0 and len(decoded[1:]) == 20:
                return True, "P2PKH (Legacy)"
        
        elif address.startswith('3'):
            decoded = base58.b58decode_check(address)
            if decoded[0] == 5 and len(decoded[1:]) == 20:
                return True, "P2SH (Multisig or Nested SegWit)"
        
        elif address.startswith('bc1'):
            hrp, data = bech32_decode(address)
            if hrp and data:
                # For bc1 addresses, data length can be 20 (P2WPKH) or 32 (P2WSH)
                return True, f"Native SegWit (length: {len(data)} bytes)"
        
        elif address.startswith('bcq1'):
            return True, "Testnet Native SegWit"
        
        return False, "Unknown address type"
    except:
        return False, "Invalid address"

def address_to_rmd160(address):
    try:
        if address.startswith('1'):
            decoded = base58.b58decode_check(address)
            if decoded[0] == 0:
                return decoded[1:].hex(), None
        elif address.startswith('3'):
            decoded = base58.b58decode_check(address)
            if decoded[0] == 5:
                return decoded[1:].hex(), None
        elif address.startswith('bc1') or address.startswith('bcq1'):
            hrp, data = bech32_decode(address)
            if hrp and data:
                return bytes(data).hex(), None
        return None, "Unsupported address format"
    except Exception as e:
        return None, str(e)

def get_public_key_from_address_legacy(address):
    try:
        url = f"https://blockchain.info/q/pubkeyaddr/{address}"
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            return "cannot be determined"

        pubkey = response.text.strip()

        if not pubkey:
            return "cannot be determined"

        if pubkey.startswith(("02", "03")) and len(pubkey) == 66:
            return "This is compressed address"

        if pubkey.startswith("04") and len(pubkey) == 130:
            return "This is uncompressed address"

        return "Key data missing"

    except Exception:
        return "cannot be determined"

def get_public_key(address):
    try:
        response = requests.get(f"https://blockchain.info/q/pubkeyaddr/{address}", timeout=5)
        return response.text if response.status_code == 200 else None
    except:
        return None

def check_address_compression(address):
    if not address.startswith('1'):
        return False, "Only addresses starting with '1' are supported"
    
    try:
        result = get_public_key_from_address_legacy(address)
        if result == "This is compressed address":
            return True, "Compressed"
        elif result == "This is uncompressed address":
            return True, "Uncompressed"
        elif result == "cannot be determined":
            return False, "Cannot determine"
        else:
            return False, result
    except Exception as e:
        return False, f"Error: {str(e)}"

# BRAIN WALLET FUNCTIONS
def brain_to_hex(passphrase):
    return sha256(passphrase.encode()).hex()

def brain_to_wif_compress(passphrase):
    hex_key = brain_to_hex(passphrase)
    return hex_to_wif(hex_key, True)

def brain_to_wif_uncompress(passphrase):
    hex_key = brain_to_hex(passphrase)
    return hex_to_wif(hex_key, False)

def brain_to_addresses(passphrase):
    hex_key = brain_to_hex(passphrase)
    return generate_all_from_hex(hex_key)

def brain_to_rmd160(passphrase, compressed=True):
    try:
        privkey = brain_to_hex(passphrase)
        pub_u, pub_c, err = hex_to_pubkey(privkey)
        if err:
            return None, err
            
        pubkey_bytes = pub_c if compressed else pub_u
        rmd160_hash = ripemd160(sha256(pubkey_bytes)).hex()
        return rmd160_hash, None
    except Exception as e:
        return None, str(e)

def brain_to_all_rmd160(passphrase):
    try:
        privkey = brain_to_hex(passphrase)
        pub_u, pub_c, err = hex_to_pubkey(privkey)
        if err:
            return None, err
            
        rmd160_uncompressed = ripemd160(sha256(pub_u)).hex()
        rmd160_compressed = ripemd160(sha256(pub_c)).hex()
        
        return {
            'Uncompressed RMD160': rmd160_uncompressed,
            'Compressed RMD160': rmd160_compressed
        }, None
    except Exception as e:
        return None, str(e)

# USER INTERFACE
def print_menu():
    print("\n" + "="*50)
    print("           ░▒▓█ BIT-UTILITY v2.0 █▓▒░ ")
    print("="*50)
    
    print("\n================= WIF OPERATIONS =================")
    print(" 1. WIF to Hex")
    print(" 2. WIF to Compressed Public Key")
    print(" 3. WIF to Uncompressed Public Key")
    print(" 4. WIF to Addresses")
    print(" 5. WIF Compressed to Uncompressed")
    print(" 6. WIF Uncompressed to Compressed")
    print(" 7. Verify WIF")
    
    print("\n================= HEX OPERATIONS =================")
    print(" 8. Hex to WIF (Compressed)")
    print(" 9. Hex to WIF (Uncompressed)")
    print("10. Hex to Compressed Public Key")
    print("11. Hex to Uncompressed Public Key")
    print("12. Hex to Addresses")
    print("13. Verify Hex Private Key")
    
    print("\n============== PUBLIC KEY OPERATIONS =============")
    print("14. Public Key (Compressed to Uncompressed)")
    print("15. Public Key (Uncompressed to Compressed)")
    print("16. Public Key to Addresses")
    print("17. Public Key (Compressed  to RMD160 Hash)")
    print("18. Public Key (Uncompressed to RMD160 Hash)")
    print("19. Verify Public Key")
    
    print("\n=============== ADDRESS OPERATIONS ===============")
    print("20. Address to Public Key (Internet Required)")
    print("21. Address to RMD160 Hash")
    print("22. Verify Address")
    print("23. Check Address Type (Compressed/Uncompressed)")
    
    print("\n============= BRAIN WALLET OPERATIONS ============")
    print("24. Brain to Hex")
    print("25. Brain to WIF (Compressed)")
    print("26. Brain to WIF (Uncompressed)")
    print("27. Brain to Addresses")
    print("28. Brain Compressed to RMD160 Hash")
    print("29. Brain Uncompressed to RMD160 Hash")
    print("30. Brain to All RMD160 Hashes")
    
    print("\n====================== EXIT ======================")
    print("31. Exit")
    print("="*50)

def print_result(title, result, error=None):
    print(f"\n{title}")
    print("-" * len(title))
    if error:
        print(f"Error: {error}")
    elif isinstance(result, dict):
        for name, value in result.items():
            print(f"{name}: {value}")
    elif isinstance(result, tuple) and len(result) == 2:
        if result[0]:
            print(f"{result[1]}")
        else:
            print(f"{result[1]}")
    elif isinstance(result, tuple) and len(result) == 3:
        if result[0]:
            print(f"{result[1]}")
            if result[2]:
                print(f"  Details: {result[2]}")
        else:
            print(f"{result[1]}")
    else:
        print(f"{result}")

def main():
    while True:
        print_menu()
        choice = input("\nEnter your choice (1-31): ").strip()
        
        try:
            # WIF OPERATIONS
            if choice == '1':  # WIF to Hex
                wif = input("Enter WIF key: ").strip()
                hex_key, compressed, err = wif_to_hex(wif)
                print_result("WIF to Hex", {
                    "Hex": hex_key,
                    "Type": "Compressed" if compressed else "Uncompressed"
                }, err)
            
            elif choice == '2':  # WIF to Compressed Public Key
                wif = input("Enter WIF key: ").strip()
                hex_key, _, err = wif_to_hex(wif)
                if err:
                    print_result("Error", None, err)
                    continue
                _, pub_c, err = hex_to_pubkey(hex_key)
                print_result("Compressed Public Key", pub_c.hex() if pub_c else None, err)
            
            elif choice == '3':  # WIF to Uncompressed Public Key
                wif = input("Enter WIF key: ").strip()
                hex_key, _, err = wif_to_hex(wif)
                if err:
                    print_result("Error", None, err)
                    continue
                pub_u, _, err = hex_to_pubkey(hex_key)
                print_result("Uncompressed Public Key", pub_u.hex() if pub_u else None, err)
            
            elif choice == '4':  # WIF to Addresses
                wif = input("Enter WIF key: ").strip()
                addresses, err = wif_to_addresses(wif)
                print_result("Generated Addresses", addresses, err)
            
            elif choice == '5':  # WIF Compressed to Uncompressed
                wif = input("Enter compressed WIF: ").strip()
                uncompressed_wif, err = wif_uncompress(wif)
                print_result("Uncompressed WIF", uncompressed_wif, err)
            
            elif choice == '6':  # WIF Uncompressed to Compressed
                wif = input("Enter uncompressed WIF: ").strip()
                compressed_wif, err = wif_compress(wif)
                print_result("Compressed WIF", compressed_wif, err)
            
            elif choice == '7':  # Verify WIF
                wif = input("Enter WIF: ").strip()
                valid, comp_type, err = verify_wif(wif)
                if err:
                    print_result("WIF Verification", (False, err))
                else:
                    print_result("WIF Verification", (True, f"Valid {comp_type} WIF"))
            
            # HEX OPERATIONS
            elif choice == '8':  # Hex to WIF (Compressed)
                hex_key = input("Enter private key (64 hex chars): ").strip()
                valid, msg = verify_hex_private_key(hex_key)
                if not valid:
                    print_result("Verification", (False, msg))
                    continue
                wif = hex_to_wif(hex_key, True)
                print_result("Compressed WIF", wif)
            
            elif choice == '9':  # Hex to WIF (Uncompressed)
                hex_key = input("Enter private key (64 hex chars): ").strip()
                valid, msg = verify_hex_private_key(hex_key)
                if not valid:
                    print_result("Verification", (False, msg))
                    continue
                wif = hex_to_wif(hex_key, False)
                print_result("Uncompressed WIF", wif)
            
            elif choice == '10':  # Hex to Compressed Public Key
                hex_key = input("Enter private key (64 hex chars): ").strip()
                valid, msg = verify_hex_private_key(hex_key)
                if not valid:
                    print_result("Verification", (False, msg))
                    continue
                _, pub_c, err = hex_to_pubkey(hex_key)
                print_result("Compressed Public Key", pub_c.hex() if pub_c else None, err)
            
            elif choice == '11':  # Hex to Uncompressed Public Key
                hex_key = input("Enter private key (64 hex chars): ").strip()
                valid, msg = verify_hex_private_key(hex_key)
                if not valid:
                    print_result("Verification", (False, msg))
                    continue
                pub_u, _, err = hex_to_pubkey(hex_key)
                print_result("Uncompressed Public Key", pub_u.hex() if pub_u else None, err)
            
            elif choice == '12':  # Hex to Addresses
                hex_key = input("Enter private key (64 hex chars): ").strip()
                valid, msg = verify_hex_private_key(hex_key)
                if not valid:
                    print_result("Verification", (False, msg))
                    continue
                addresses, err = generate_all_from_hex(hex_key)
                print_result("Generated Addresses", addresses, err)
            
            elif choice == '13':  # Verify Hex Private Key
                hex_str = input("Enter private key in hex: ").strip()
                valid, msg = verify_hex_private_key(hex_str)
                print_result("Private Key Verification", (valid, msg))
            
            # PUBLIC KEY OPERATIONS
            elif choice == '14':  # Compressed to Uncompressed
                pubkey = input("Enter compressed public key (02/03): ").strip()
                uncompressed = uncompress_pubkey(pubkey)
                if uncompressed:
                    print_result("Uncompressed Public Key", uncompressed)
                else:
                    print_result("Error", None, "Invalid compressed public key")
            
            elif choice == '15':  # Uncompressed to Compressed
                pubkey = input("Enter uncompressed public key (04): ").strip()
                compressed = compress_pubkey(pubkey)
                if compressed:
                    print_result("Compressed Public Key", compressed)
                else:
                    print_result("Error", None, "Invalid uncompressed public key")
            
            elif choice == '16':  # Pubkey to Addresses
                pubkey = input("Enter public key (02/03/04): ").strip()
                addresses, err = process_public_key(pubkey)
                print_result("Generated Addresses", addresses, err)
            
            elif choice == '17':  # Compressed Public Key to RMD160
                pubkey = input("Enter compressed public key (02/03): ").strip()
                rmd160_hash, err = pubkey_to_rmd160(pubkey, compressed=True)
                print_result("Compressed RMD160 Hash", rmd160_hash, err)
            
            elif choice == '18':  # Uncompressed Public Key to RMD160
                pubkey = input("Enter uncompressed public key (04): ").strip()
                rmd160_hash, err = pubkey_to_rmd160(pubkey, compressed=False)
                print_result("Uncompressed RMD160 Hash", rmd160_hash, err)
            
            elif choice == '19':  # Verify Public Key
                pubkey = input("Enter public key (02/03/04): ").strip()
                valid, msg = verify_public_key(pubkey)
                print_result("Public Key Verification", (valid, msg))
            
            # ADDRESS OPERATIONS
            elif choice == '20':  # Address to Public Key
                addr = input("Enter Bitcoin address: ").strip()
                valid, addr_type = verify_address(addr)
                if not valid:
                    print_result("Address Verification", (False, addr_type))
                    continue
                pubkey = get_public_key(addr)
                if pubkey:
                    print_result("Public Key", pubkey)
                else:
                    print_result("Error", None, "Failed to retrieve public key")
            
            elif choice == '21':  # Address to RMD160
                addr = input("Enter Bitcoin address: ").strip()
                rmd, err = address_to_rmd160(addr)
                print_result("RIPEMD160 Hash", rmd, err)
            
            elif choice == '22':  # Verify Address
                address = input("Enter Bitcoin address: ").strip()
                valid, addr_type = verify_address(address)
                print_result("Address Verification", (valid, addr_type))
            
            elif choice == '23':  # Check Address Compression
                address = input("Enter Bitcoin address: ").strip()
                if not address.startswith('1'):
                    print_result("Address Check", (False, "Only addresses starting with '1' are supported"))
                    continue
                success, result = check_address_compression(address)
                print_result("Address Compression Check", (success, result))
            
            # BRAIN WALLET OPERATIONS
            elif choice == '24':  # Brain to Hex
                phrase = input("Enter passphrase: ").strip()
                hex_key = brain_to_hex(phrase)
                print_result("Brain Wallet to Hex", {
                    "Passphrase": phrase,
                    "Private Key": hex_key
                })
            
            elif choice == '25':  # Brain to WIF (Compressed)
                phrase = input("Enter passphrase: ").strip()
                wif = brain_to_wif_compress(phrase)
                print_result("Brain Wallet to WIF (Compressed)", wif)
            
            elif choice == '26':  # Brain to WIF (Uncompressed)
                phrase = input("Enter passphrase: ").strip()
                wif = brain_to_wif_uncompress(phrase)
                print_result("Brain Wallet to WIF (Uncompressed)", wif)
            
            elif choice == '27':  # Brain to Addresses
                phrase = input("Enter passphrase: ").strip()
                addresses, err = brain_to_addresses(phrase)
                print_result("Brain Wallet Addresses", addresses, err)
            
            elif choice == '28':  # Brain Compressed to RMD160
                phrase = input("Enter passphrase: ").strip()
                rmd160_hash, err = brain_to_rmd160(phrase, compressed=True)
                print_result("Brain Wallet Compressed RMD160", rmd160_hash, err)
            
            elif choice == '29':  # Brain Uncompressed to RMD160
                phrase = input("Enter passphrase: ").strip()
                rmd160_hash, err = brain_to_rmd160(phrase, compressed=False)
                print_result("Brain Wallet Uncompressed RMD160", rmd160_hash, err)
            
            elif choice == '30':  # Brain to All RMD160
                phrase = input("Enter passphrase: ").strip()
                hashes, err = brain_to_all_rmd160(phrase)
                print_result("Brain Wallet All RMD160 Hashes", hashes, err)
            
            # EXIT
            elif choice == '31':
                print("\nGoodbye!")
                break
            
            else:
                print("\nInvalid choice! Please enter a number between 1-31.")
        
        except Exception as e:
            print(f"\nUnexpected error: {str(e)}")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()