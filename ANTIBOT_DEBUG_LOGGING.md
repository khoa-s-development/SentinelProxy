# AntiBot Debug Logging Enhancement

This document describes the enhanced debug logging system added to the AntiBot class, inspired by the Sonar anti-bot project.

## Overview

The AntiBot system now includes comprehensive debug logging for lobby/verification world connections and player verification processes. This follows best practices from the Sonar anti-bot project for detecting and tracking bot behavior.

## Debug Logging Categories

### 1. Connection Logging (`[CONNECTION]`)
- Initial player connections
- IP address tracking
- Virtual host information
- Verification exemption status
- Target server determination

### 2. Lobby Join Logging (`[LOBBY-JOIN]`)
- Detailed connection information when joining verification world
- Session creation/reuse
- Player state tracking
- Connection statistics per IP
- Verification task scheduling

### 3. Movement Logging (`[LOBBY-MOVEMENT]`)
- Player movement in verification world
- Position deltas and distances
- Jump and crouch detection
- Movement timing analysis
- Suspicious pattern detection

### 4. Interaction Logging (`[LOBBY-INTERACTION]`)
- Player interactions in verification world
- Interaction counts and timing
- Verification score updates
- First interaction milestones

### 5. Verification Analysis (`[LOBBY-ANALYSIS]`)
- Comprehensive verification metrics
- Movement complexity calculations
- Natural timing assessment
- Pass/fail determinations

### 6. Result Logging (`[LOBBY-RESULT]`)
- Final verification results
- Player actions (kick/transfer)
- Suspicious player marking

### 7. Transfer Logging (`[TRANSFER]`)
- Server transfer initiation
- Target server determination
- Transfer scheduling and execution
- Cleanup operations

### 8. Disconnect Logging (`[DISCONNECT]`)
- Disconnection during verification
- Session completion status
- Early departure detection
- Cleanup operations

## Key Features Inspired by Sonar

### 1. Comprehensive Session Tracking
- Track all player interactions in verification world
- Monitor movement patterns and timing
- Detect bot-like behavior patterns

### 2. Suspicious Timing Detection
- Identify overly consistent movement timing (bot behavior)
- Flag players with robotic movement patterns
- Use natural timing variations as human indicators

### 3. Verification Scoring System
- Multi-factor scoring based on:
  - Movement count and distance
  - Interaction frequency
  - Movement complexity
  - Natural timing patterns
  - Action variety (jump, crouch, interact)

### 4. Enhanced Debugging Information
- Detailed connection analysis
- Real-time verification progress
- Comprehensive result logging
- Early detection of bot patterns

## Configuration

Debug logging can be controlled through the standard logging configuration. Set the log level for `com.velocitypowered.proxy.connection.antiddos.AntiBot` to:

- `DEBUG` - See all debug messages including detailed movement and verification analysis
- `INFO` - See connection, verification results, and transfer information
- `WARN` - See only warnings and errors

## Log Message Examples

### Player Joining Verification World
```
[INFO] [LOBBY-JOIN] Player TestPlayer connected to verification world (session: NEW)
[DEBUG] [LOBBY-JOIN] Player TestPlayer (uuid-here) connecting to verification world from 192.168.1.100
[DEBUG] [LOBBY-JOIN] Session details - Start position: [0.0, 64.0, 0.0], Start time: 1672531200000
[DEBUG] [LOBBY-JOIN] IP 192.168.1.100 currently has 1 active connections
[DEBUG] [LOBBY-JOIN] Player state - Verified: false, Suspicious: false, Failed checks: 0
```

### Movement in Verification World
```
[DEBUG] [LOBBY-MOVEMENT] Player TestPlayer moved in mini-world
[DEBUG] [LOBBY-MOVEMENT]   Position: [1.50, 64.00, 2.30]
[DEBUG] [LOBBY-MOVEMENT]   Delta: [0.50, 0.00, 0.30], Distance: 0.58
[DEBUG] [LOBBY-MOVEMENT]   Move count: 5, Total distance: 3.24
[DEBUG] [LOBBY-MOVEMENT]   Time since last move: 150 ms
```

### Verification Results
```
[DEBUG] [LOBBY-ANALYSIS] Player TestPlayer verification analysis:
[DEBUG] [LOBBY-ANALYSIS]   Movement count: 12
[DEBUG] [LOBBY-ANALYSIS]   Interaction count: 3
[DEBUG] [LOBBY-ANALYSIS]   Distance moved: 5.67
[DEBUG] [LOBBY-ANALYSIS]   Total path distance: 8.92
[DEBUG] [LOBBY-ANALYSIS]   Movement complexity: 7.50
[DEBUG] [LOBBY-ANALYSIS]   Has jumped: true
[DEBUG] [LOBBY-ANALYSIS]   Has crouched: false
[DEBUG] [LOBBY-ANALYSIS]   Has interacted: true
[DEBUG] [LOBBY-ANALYSIS]   Natural timing: true
[DEBUG] [LOBBY-ANALYSIS]   Session duration: 12450 ms
[DEBUG] [LOBBY-ANALYSIS]   RESULT: PASSED
[INFO] [LOBBY-RESULT] Player TestPlayer PASSED verification check
```

## Benefits

1. **Enhanced Bot Detection**: More detailed tracking enables better bot identification
2. **Debugging Support**: Comprehensive logs help diagnose verification issues
3. **Performance Monitoring**: Track verification system performance and effectiveness
4. **Security Analysis**: Identify attack patterns and improve defenses
5. **Administrative Oversight**: Monitor player verification process in real-time

## Compatibility

This enhancement is fully backward compatible and does not change the existing API or configuration requirements. All new logging is added without affecting existing functionality.
