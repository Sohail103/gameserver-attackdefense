#!/usr/bin/env python3
"""
generate_ssl_cert.py

Generate self-signed SSL certificate for HTTPS support.
This creates cert.pem and key.pem files for the CTF server.
"""

import subprocess
import sys
import os

def generate_certificate():
    """Generate self-signed SSL certificate using openssl"""
    
    print("=" * 60)
    print("Generating Self-Signed SSL Certificate")
    print("=" * 60)
    print()
    
    # Check if openssl is available
    try:
        subprocess.run(["openssl", "version"], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE,
                      check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Error: openssl is not installed or not in PATH")
        print()
        print("Install openssl:")
        print("  Ubuntu/Debian: sudo apt install openssl")
        print("  macOS: brew install openssl")
        print("  NixOS: Add 'openssl' to your shell.nix")
        sys.exit(1)
    
    # Check if files already exist
    if os.path.exists("cert.pem") or os.path.exists("key.pem"):
        response = input("⚠️  cert.pem or key.pem already exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Cancelled.")
            sys.exit(0)
    
    # Generate private key and certificate
    print("Generating private key and certificate...")
    print()
    
    cmd = [
        "openssl", "req", "-x509",
        "-newkey", "rsa:4096",
        "-keyout", "key.pem",
        "-out", "cert.pem",
        "-days", "365",
        "-nodes",  # Don't encrypt the private key
        "-subj", "/C=US/ST=State/L=City/O=CTF/CN=ctf-gameserver"
    ]
    
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error generating certificate: {e}")
        sys.exit(1)
    
    print()
    print("=" * 60)
    print("✅ SSL Certificate Generated Successfully!")
    print("=" * 60)
    print()
    print("Files created:")
    print("  📄 cert.pem - SSL certificate")
    print("  🔑 key.pem  - Private key")
    print()
    print("To use with the CTF server:")
    print("  python main.py --ssl-cert cert.pem --ssl-key key.pem")
    print()
    print("⚠️  NOTE: This is a self-signed certificate!")
    print("   Clients will need to use -k flag with curl:")
    print("   curl -k https://...")
    print()
    print("   Or accept the security warning in browsers.")
    print("=" * 60)


if __name__ == "__main__":
    generate_certificate()
