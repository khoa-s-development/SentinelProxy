# AntiBot Verification Server Test Script (PowerShell)
# This script helps test the AntiBot verification server setup

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "SentinalsProxy AntiBot Verification Test" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

# Test 1: Check if verification server is running
Write-Host "Testing verification server availability..." -ForegroundColor Yellow
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.ConnectAsync("127.0.0.1", 25569).Wait(5000)
    if ($tcpClient.Connected) {
        Write-Host "✓ Verification server is running on port 25569" -ForegroundColor Green
        $tcpClient.Close()
    } else {
        throw "Connection failed"
    }
} catch {
    Write-Host "✗ Verification server is NOT running on port 25569" -ForegroundColor Red
    Write-Host "  Please start the verification server before testing" -ForegroundColor Yellow
    exit 1
}

# Test 2: Check main lobby server
Write-Host "Testing main lobby server availability..." -ForegroundColor Yellow
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.ConnectAsync("127.0.0.1", 25566).Wait(5000)
    if ($tcpClient.Connected) {
        Write-Host "✓ Main lobby server is running on port 25566" -ForegroundColor Green
        $tcpClient.Close()
    } else {
        throw "Connection failed"
    }
} catch {
    Write-Host "✗ Main lobby server is NOT running on port 25566" -ForegroundColor Red
    Write-Host "  Please start the main lobby server before testing" -ForegroundColor Yellow
    exit 1
}

# Test 3: Check proxy server
Write-Host "Testing proxy server availability..." -ForegroundColor Yellow
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.ConnectAsync("127.0.0.1", 25565).Wait(5000)
    if ($tcpClient.Connected) {
        Write-Host "✓ Proxy server is running on port 25565" -ForegroundColor Green
        $tcpClient.Close()
    } else {
        throw "Connection failed"
    }
} catch {
    Write-Host "✗ Proxy server is NOT running on port 25565" -ForegroundColor Red
    Write-Host "  Please start the proxy server before testing" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "All servers are running! Test setup complete." -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To test the AntiBot system:" -ForegroundColor Yellow
Write-Host "1. Connect to the proxy at 127.0.0.1:25565" -ForegroundColor White
Write-Host "2. You should be sent to the verification world first" -ForegroundColor White
Write-Host "3. Move around in the verification world" -ForegroundColor White
Write-Host "4. After verification, you'll be transferred to the lobby" -ForegroundColor White
Write-Host ""
Write-Host "Monitor the proxy logs for verification messages." -ForegroundColor Yellow
Write-Host "If you see 'Verification server not found' errors," -ForegroundColor Yellow
Write-Host "make sure the verification server is running on port 25569." -ForegroundColor Yellow
