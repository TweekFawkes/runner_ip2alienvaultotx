#!/usr/bin/env python3
"""
Demo script showing OTX IP lookup functionality
"""

import subprocess
import sys

def run_demo():
    print("=== AlienVault OTX IP Lookup Demo ===\n")
    
    # Test cases
    test_cases = [
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("invalid-ip", "Invalid IP (should fail)")
    ]
    
    for ip, description in test_cases:
        print(f"Testing {ip} ({description}):")
        print("-" * 50)
        
        try:
            # Run the app with a dummy API key
            result = subprocess.run([
                sys.executable, "app.py", ip, "--api-key", "demo_key"
            ], capture_output=True, text=True, timeout=30)
            
            print("STDOUT:")
            print(result.stdout)
            if result.stderr:
                print("STDERR:")
                print(result.stderr)
            print(f"Exit Code: {result.returncode}")
            
        except subprocess.TimeoutExpired:
            print("Command timed out")
        except Exception as e:
            print(f"Error running command: {e}")
        
        print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    run_demo() 