# AntiBot Verification Server Setup Guide

## Overview
This document explains how to set up the AntiBot verification server for SentinalsProxy. The verification server is a crucial component that allows the AntiBot system to validate that connecting players are human and not bots.

## Quick Start

### 1. Understanding the System
- **Main Proxy**: `127.0.0.1:25565` - Players connect here
- **Verification Server**: `127.0.0.1:25569` - Where players go for verification
- **Lobby Server**: `127.0.0.1:25566` - Where players go after verification

### 2. Setup the Verification Server
1. **Download a Minecraft server** (Paper/Spigot/Vanilla recommended)
2. **Create a new folder** for the verification server
3. **Configure `server.properties`**:
   ```properties
   server-port=25569
   online-mode=false
   level-type=flat
   spawn-protection=0
   gamemode=adventure
   difficulty=peaceful
   max-players=100
   allow-flight=true
   ```

### 3. Start the Servers
1. **Start the verification server** first on port 25569
2. **Start your main lobby server** on port 25566
3. **Start the proxy** on port 25565

### 4. Test the Setup
Run the test script:
- **Windows**: `.\test-antibot-setup.ps1`
- **Linux/Mac**: `./test-antibot-setup.sh`

## Configuration

### Current Settings (in `velocity.toml`)
```toml
[antibot]
enabled = true
kick-enabled = false                    # Start with warnings only
debug-mode = false                      # Set to true for troubleshooting
mini-world-check-enabled = true        # Main verification method
mini-world-duration = 10               # Seconds to complete verification
mini-world-min-movements = 3           # Minimum movement packets
mini-world-min-distance = 2.0          # Minimum distance to move

[layer4-protection]
enabled = true
debug-mode = false                      # Set to true for troubleshooting
advanced-logging-enabled = false       # Reduces log spam
```

## How It Works

### 1. Player Connection Flow
```
Player → Proxy → Verification Server → Main Lobby
```

### 2. Verification Process
1. Player connects to proxy at `127.0.0.1:25565`
2. AntiBot system redirects player to verification server
3. Player must move around in the verification world
4. After successful verification, player is transferred to lobby
5. Future connections skip verification (if configured)

### 3. Log Messages
- `[VERIFICATION] Player X requires verification` - Player being sent to verification
- `[VERIFICATION] Player X completed verification` - Player passed verification
- `[VERIFICATION] Verification server not found` - Verification server is down

## Troubleshooting

### "Verification server not found" Error
**Cause**: The verification server is not running on port 25569
**Solution**: 
1. Start the verification server
2. Check it's running on the correct port
3. Verify firewall settings

### Players Bypass Verification
**Cause**: One of these issues:
1. Verification server is not running
2. `mini-world-check-enabled` is set to `false`
3. `antibot.enabled` is set to `false`

**Solution**: 
1. Check configuration in `velocity.toml`
2. Ensure verification server is running
3. Restart the proxy after configuration changes

### Log Spam
**Cause**: Debug mode is enabled
**Solution**: Set `debug-mode = false` in both `[antibot]` and `[layer4-protection]` sections

### Players Can't Move in Verification World
**Cause**: Verification world has movement restrictions
**Solution**: 
1. Set `gamemode=adventure` in verification server
2. Set `allow-flight=true`
3. Ensure spawn protection is disabled

## Advanced Configuration

### Increasing Security
```toml
[antibot]
kick-enabled = true                     # Enable kicking after testing
kick-threshold = 3                      # Lower threshold
mini-world-duration = 15               # Longer verification time
mini-world-min-movements = 5           # More movements required
connection-rate-limit = 2              # Stricter rate limiting
```

### Performance Optimization
```toml
[antibot]
check-only-first-join = true           # Only check first join
dns-check-enabled = false              # Disable slow DNS checks
latency-check-enabled = false          # Disable latency checks

[layer4-protection]
advanced-logging-enabled = false       # Reduce log output
```

## Server Requirements

### Minimum Requirements
- **Verification Server**: 
  - RAM: 512MB minimum
  - CPU: Single core sufficient
  - Network: Low bandwidth usage
  - Storage: 1GB for world and logs

### Recommended Setup
- **Verification Server**: Simple flat world with basic spawn area
- **World Type**: Flat or void world for fastest loading
- **Plugins**: None required, keep it lightweight
- **Monitoring**: Basic uptime monitoring recommended

## Security Considerations

### Important Notes
1. **Verification Server Security**: Keep it simple and secure
2. **Network Security**: Consider firewall rules
3. **Monitoring**: Monitor verification server uptime
4. **Backup**: Backup verification world periodically
5. **Updates**: Keep server software updated

### Production Checklist
- [ ] Verification server running on port 25569
- [ ] Main lobby server running on port 25566
- [ ] Proxy configured with correct server addresses
- [ ] Debug mode disabled in production
- [ ] Log monitoring set up
- [ ] Backup procedures in place
- [ ] Performance monitoring enabled

## Support

If you encounter issues:
1. Enable debug mode temporarily
2. Check server logs for error messages
3. Use the test scripts to verify connectivity
4. Ensure all required ports are open
5. Check server resource usage

## Example Verification World Setup

### Simple Flat World
1. Create a superflat world
2. Set spawn at Y=4 (above bedrock)
3. Add basic spawn platform (5x5 blocks)
4. Consider adding simple instructions with signs
5. Keep it minimal for best performance

### Signs for Player Instructions
```
[Sign 1]
Welcome to
Verification
Please move around
to continue

[Sign 2]
Walk forward
and back
to prove you're
human
```

This setup provides a balance between security and user experience while maintaining optimal performance.
