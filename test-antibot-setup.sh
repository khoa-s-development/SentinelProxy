#!/bin/bash

# AntiBot Verification Server Test Script
# This script helps test the AntiBot verification server setup

echo "==============================================="
echo "SentinalsProxy AntiBot Verification Test"
echo "==============================================="

# Test 1: Check if verification server is running
echo "Testing verification server availability..."
if timeout 5 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/25569'; then
    echo "✓ Verification server is running on port 25569"
else
    echo "✗ Verification server is NOT running on port 25569"
    echo "  Please start the verification server before testing"
    exit 1
fi

# Test 2: Check main lobby server
echo "Testing main lobby server availability..."
if timeout 5 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/25566'; then
    echo "✓ Main lobby server is running on port 25566"
else
    echo "✗ Main lobby server is NOT running on port 25566"
    echo "  Please start the main lobby server before testing"
    exit 1
fi

# Test 3: Check proxy server
echo "Testing proxy server availability..."
if timeout 5 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/25565'; then
    echo "✓ Proxy server is running on port 25565"
else
    echo "✗ Proxy server is NOT running on port 25565"
    echo "  Please start the proxy server before testing"
    exit 1
fi

echo ""
echo "==============================================="
echo "All servers are running! Test setup complete."
echo "==============================================="
echo ""
echo "To test the AntiBot system:"
echo "1. Connect to the proxy at 127.0.0.1:25565"
echo "2. You should be sent to the verification world first"
echo "3. Move around in the verification world"
echo "4. After verification, you'll be transferred to the lobby"
echo ""
echo "Monitor the proxy logs for verification messages."
echo "If you see 'Verification server not found' errors,"
echo "make sure the verification server is running on port 25569."
