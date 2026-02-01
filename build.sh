#!/bin/bash
set -e

# Compile the terminal server for Unraid (Linux AMD64)
echo "Compiling raidman for Linux AMD64..."
GOOS=linux GOARCH=amd64 go build -o raidman src/cmd/app/main.go

echo "Build complete: raidman"

echo "To publish:"
echo "1. Ensure you are in the correct git repository for 'windium/raidman-plugin'."
echo "2. Commit and push: raidman.plg, raidman.conf, src/, go.mod, go.sum"
echo "3. Create Release tag v2026.01.09"
echo "4. Upload 'raidman' binary asset."
