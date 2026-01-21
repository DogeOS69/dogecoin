#!/bin/bash

# installs test dependencies for Dogecoin Core RPC tests

set -e

# Detect if we're in an externally-managed environment (PEP 668)
PIP_ARGS="--user"
if python3 -c "import sys; sys.exit(0 if hasattr(sys, 'base_prefix') else 1)" 2>/dev/null; then
    # Check for externally-managed marker
    STDLIB_PATH=$(python3 -c "import sysconfig; print(sysconfig.get_path('stdlib'))")
    if [ -f "$STDLIB_PATH/EXTERNALLY-MANAGED" ]; then
        echo "Detected externally-managed Python environment (PEP 668)"
        PIP_ARGS="--user --break-system-packages"
    fi
fi

# Python version check for asyncore compatibility
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

echo "Python version: $PYTHON_VERSION"

# Install pyasyncore for Python 3.12+ (asyncore was removed)
if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 12 ]; then
    echo "Installing pyasyncore for Python 3.12+ compatibility..."
    python3 -m pip install pyasyncore $PIP_ARGS || {
        echo "WARNING: Failed to install pyasyncore via pip."
        echo "On Arch Linux, try: sudo pacman -S python-pyasyncore"
    }
fi

# Install ltc_scrypt
file=v1.0.1.tar.gz
echo "Downloading ltc_scrypt..."
curl -L -O https://github.com/dogecoin/ltc-scrypt/archive/refs/tags/$file
echo "e866ade37fb27439ae0ca32f1ee4ad32be428c1fdac9bcc988b36c68648ff0de  $file" | sha256sum -c
echo "Installing ltc_scrypt..."
python3 -m pip install $file $PIP_ARGS
rm -rf $file

echo ""
echo "Dependencies installed successfully!"
echo "Note: You may also need python3-zmq (pyzmq). Install via your package manager:"
echo "  Debian/Ubuntu: sudo apt-get install python3-zmq"
echo "  Arch Linux:    sudo pacman -S python-pyzmq"
echo "  macOS:         pip3 install pyzmq"
