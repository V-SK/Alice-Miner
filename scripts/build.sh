#!/bin/bash
# Full build script for Alice Miner

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."

cd "$PROJECT_DIR"

echo "=========================================="
echo "  Alice Miner Build Script"
echo "=========================================="

# Check prerequisites
echo ""
echo "Checking prerequisites..."

if ! command -v node &> /dev/null; then
    echo "Error: Node.js not found. Please install Node.js 18+"
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo "Error: Rust not found. Please install Rust 1.75+"
    exit 1
fi

echo "✓ Node.js $(node --version)"
echo "✓ Rust $(cargo --version)"

# Install dependencies
echo ""
echo "Installing dependencies..."
npm install

# Generate icons if not present
if [ ! -f "src-tauri/icons/icon.png" ]; then
    echo ""
    echo "Generating icons..."
    npx tauri icon public/alice-logo.svg || echo "Warning: Icon generation failed. Using placeholder."
fi

# Build
echo ""
echo "Building application..."
npm run tauri build

# Output
echo ""
echo "=========================================="
echo "  Build Complete!"
echo "=========================================="

if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Output: src-tauri/target/release/bundle/dmg/"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Output: src-tauri/target/release/bundle/appimage/"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    echo "Output: src-tauri/target/release/bundle/msi/"
fi
