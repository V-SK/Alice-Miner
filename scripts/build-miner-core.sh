#!/bin/bash
# Build alice-miner-core binary using PyInstaller

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINER_DIR="$SCRIPT_DIR/../miner-core"
OUTPUT_DIR="$SCRIPT_DIR/../src-tauri/binaries"

echo "Building alice-miner-core..."

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if miner script exists
if [ ! -f "$MINER_DIR/alice_miner_v2.py" ]; then
    echo "Error: alice_miner_v2.py not found in $MINER_DIR"
    echo "Please copy the miner script to miner-core/ directory"
    exit 1
fi

cd "$MINER_DIR"

# Install dependencies if needed
pip install pyinstaller torch --quiet

# Build with PyInstaller
pyinstaller \
    --onefile \
    --name alice-miner-core \
    --hidden-import torch \
    --hidden-import numpy \
    --hidden-import requests \
    --hidden-import websocket \
    --strip \
    --noconfirm \
    alice_miner_v2.py

# Copy to binaries directory
cp dist/alice-miner-core "$OUTPUT_DIR/"

echo "Build complete: $OUTPUT_DIR/alice-miner-core"
