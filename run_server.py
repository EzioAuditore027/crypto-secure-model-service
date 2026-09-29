"""
Run Script for Cryptography-Based Secure Model Service
Starts the HTTP server and API service.
"""
import sys
import os

# Add root directory to python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server.app import run

if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run(host="127.0.0.1", port=port)
