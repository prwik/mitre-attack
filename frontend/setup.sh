#!/bin/bash
# Frontend Setup Script
# Sets up both ATT&CK Navigator and ATLAS Navigator

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== MITRE ATT&CK Navigator Frontend Setup ==="

# Check for Node.js
if ! command -v node &> /dev/null; then
    echo "Error: Node.js is not installed. Please install Node.js v22 or higher."
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "Warning: Node.js v$NODE_VERSION detected. Recommended version is v22+."
fi

# Clone ATT&CK Navigator if not exists
if [ ! -d "attack-navigator" ]; then
    echo "Cloning ATT&CK Navigator..."
    git clone https://github.com/mitre-attack/attack-navigator.git
else
    echo "ATT&CK Navigator already exists, updating..."
    cd attack-navigator && git pull && cd ..
fi

# Clone ATLAS Navigator if not exists
if [ ! -d "atlas-navigator" ]; then
    echo "Cloning ATLAS Navigator..."
    git clone https://github.com/mitre-atlas/atlas-navigator.git
else
    echo "ATLAS Navigator already exists, updating..."
    cd atlas-navigator && git pull && cd ..
fi

# Install ATT&CK Navigator dependencies
echo "Installing ATT&CK Navigator dependencies..."
cd attack-navigator/nav-app
npm install

# Copy custom configuration
echo "Applying custom configuration..."
cp ../../config/attack-config.json src/assets/config.json 2>/dev/null || true

cd ../..

# Install ATLAS Navigator dependencies
echo "Installing ATLAS Navigator dependencies..."
cd atlas-navigator/nav-app
npm install

# Copy custom configuration
cp ../../config/atlas-config.json src/assets/config.json 2>/dev/null || true

cd ../..

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To start ATT&CK Navigator:"
echo "  cd attack-navigator/nav-app && ng serve"
echo "  Open http://localhost:4200"
echo ""
echo "To start ATLAS Navigator:"
echo "  cd atlas-navigator/nav-app && ng serve --port 4201"
echo "  Open http://localhost:4201"
echo ""
echo "To start the backend API:"
echo "  cd ../backend && uvicorn app.main:app --reload"
echo "  API docs at http://localhost:8000/docs"
