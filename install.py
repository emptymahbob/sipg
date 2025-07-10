#!/usr/bin/env python3
"""
Simple installation script for SIPG.
"""

import subprocess
import sys
import os
from pathlib import Path


def run_command(command, description):
    """Run a command and handle errors."""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        if e.stdout:
            print(f"stdout: {e.stdout}")
        if e.stderr:
            print(f"stderr: {e.stderr}")
        return False


def main():
    """Main installation function."""
    print("🚀 SIPG Installation Script")
    print("=" * 40)
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        sys.exit(1)
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    # Install dependencies
    if not run_command("pip install -r requirements.txt", "Installing dependencies"):
        print("❌ Failed to install dependencies")
        sys.exit(1)
    
    # Install SIPG in development mode
    if not run_command("pip install -e .", "Installing SIPG"):
        print("❌ Failed to install SIPG")
        sys.exit(1)
    
    print("\n🎉 Installation completed successfully!")
    print("\n📋 Next steps:")
    print("1. Get your Shodan API key from https://account.shodan.io/")
    print("2. Configure SIPG: sipg configure")
    print("3. Start searching: sipg search 'your-query'")
    print("4. See examples: sipg examples")
    print("5. Get help: sipg --help")


if __name__ == "__main__":
    main() 