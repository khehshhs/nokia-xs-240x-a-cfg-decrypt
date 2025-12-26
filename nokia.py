#!/usr/bin/env python3

# NOTE: This script requires the PyCryptodome library (or PyCrypto).
# You may need to install it first: pip3 install pycryptodome

import sys
import zlib
import struct
import binascii
import datetime
try:
    from Crypto.Cipher import AES
except ImportError:
    pass # Dependency check handled later

# --- GLOBAL VARIABLES ---
big_endian = True
encrypted_cfg = False

def u32(val):
    return struct.unpack('>I' if big_endian else '<I', val)[0]

def p32(val):
    return struct.pack('>I' if big_endian else '<I', val)

def checkendian(cfg):
    # Check for the configuration file magic number
    if (cfg[0:4] == b'\x00\x12\x31\x23'): # Big Endian Magic
        return True
    elif (cfg[0:4] == b'\x23\x31\x12\x00'): # Little Endian Magic
        return False
    else:
        return None

class RouterCrypto:
    """Handles the AES decryption and encryption for the configuration file."""
    def __init__(self):
        # Key and IV for AES - CORRECTED for Nokia XS-240X-A (XGS-PON)
        key = 'F8 4A 90 B1 C5 C7 11 9F 4A 24 AC 88 F0 C6 27 50 B9 4D 05 91 6F 08 D9 01 4F 35 0C A4 F8 2B 45 42'
        iv  = '87 D0 E1 59 79 36 29 48 4D 59 CC A3 F9 54 D5 47'

        # create AES-256-CBC cipher
        self.cipher = AES.new(
            bytes(bytearray.fromhex(key.replace(' ', ''))),
            AES.MODE_CBC,
            bytes(bytearray.fromhex(iv.replace(' ', '')))
        )

    def decrypt(self, data):
        output = self.cipher.decrypt(data)
        # remove PKCS#7 padding
        pad_size = output[-1]
        return output[:-pad_size]


# --- MAIN UNPACK LOGIC (-u) ---

if (len(sys.argv) == 3 and sys.argv[1] == '-u'):
    
    # Dependency check
    if 'AES' not in globals():
        print("\nError: The 'pycryptodome' library is required.")
        print("Please install it: pip3 install pycryptodome\n")
        sys.exit(1)

    print('\n-> Starting configuration file unpacker...')

    # Read the cfg file
    try:
        with open(sys.argv[2], 'rb') as cf:
            cfg_data = cf.read()
    except FileNotFoundError:
        print(f"Error: File not found: {sys.argv[2]}\n")
        sys.exit(1)

    # Decryption Check
    big_endian = checkendian(cfg_data)
    if big_endian is None:
        try:
            decrypted = RouterCrypto().decrypt(cfg_data)
            big_endian = checkendian(decrypted)
        except Exception:
            pass
        
        if big_endian is None:
            print('\nError: Invalid cfg file/magic. Decryption failed, or key is wrong.\n')
            sys.exit(1)

        print('-> Encrypted cfg detected. Decryption successful.')
        cfg_data = decrypted
        encrypted_cfg = True

    else:
        print('-> Unencrypted cfg detected.')

    # Log endianness
    if big_endian:
        print('-> Big endian CPU detected')
    else:
        print('-> Little endian CPU detected')

    # Extract header fields
    fw_magic = u32(cfg_data[0x10:0x14])
    data_size = u32(cfg_data[4:8])
    compressed = cfg_data[0x14 : 0x14 + data_size]
    checksum = u32(cfg_data[8:12])
    print('-> fw_magic = ' + hex(fw_magic))

    # Verify checksum
    if (binascii.crc32(compressed) & 0xFFFFFFFF) != checksum:
        print('\nError: CRC32 checksum failed. The file is corrupt.\n')
        sys.exit(1)
    
    print('-> CRC32 check passed. Attempting decompression...')
    
    # --- ROBUST DECOMPRESSION WITH 16-BYTE OFFSET FIX ---
    xml_data = None
    
    # List of Zlib window sizes (wbits) to try
    wbits_to_try = list(range(-15, -7)) + [15, 31, 47]
    
    # CRITICAL FIX: The proprietary header is 16 bytes (0x10)
    offsets = [0, 4, 8, 12, 16] 
    
    for offset in offsets:
        compressed_offset = compressed[offset:]
        
        for wbits in wbits_to_try:
            try:
                xml_data = zlib.decompress(compressed_offset, wbits)
                if xml_data:
                    print(f'-> SUCCESS! Unpacked with {offset} byte header skipped and Zlib wbits={wbits}.')
                    break 
            except zlib.error:
                pass 
        
        if xml_data:
            break 

    
    if not xml_data:
        print('\nError: Decompression failed. The 16-byte proprietary header fix failed.')
        print('The file may be using a non-Deflate compression method.')
        sys.exit(1)
    # --- END OF ROBUST CHECK ---

    # Output the xml file
    out_filename = 'config-%s.xml' % datetime.datetime.now().strftime('%d%m%Y-%H%M%S')
    with open(out_filename, 'wb') as of:
        of.write(xml_data)

    print('\nSuccessfully unpacked as: ' + out_filename)
    print('\n# Repack command:')
    print('%s %s %s %s\n' % (sys.argv[0], ('-pb' if big_endian else '-pl') + ('e' if encrypted_cfg else ''), out_filename, hex(fw_magic)))

# --- USAGE / HELP ---
else:

    print('\n#\n# Nokia/Alcatel-Lucent Router Configuration Tool (XS-240X-A Key)\n#\n')
    print('# Usage:\n')
    print(sys.argv[0] + ' -u CFG.cfg\n')
    print('# Install dependencies: pip3 install pycryptodome\n')