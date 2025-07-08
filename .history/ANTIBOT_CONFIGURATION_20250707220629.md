# AntiBot and DDoS Protection Configuration Guide

This document explains all the configuration options available for the AntiBot and DDoS protection systems in SentinalsProxy.

## Configuration File

All settings are configured in the `velocity.toml` file under specific sections:
- `[antibot]` - AntiBot protection settings
- `[layer4-protection]` - Layer 4 (TCP/UDP) DDoS protection
- `[layer7-protection]` - Layer 7 (Minecraft protocol) protection

## AntiBot Configuration (`[antibot]`)

### Basic Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable or disable the entire AntiBot system |
| `kick-enabled` | boolean | `false` | Whether to kick players who fail checks (true) or just log warnings (false) |
| `check-only-first-join` | boolean | `true` | Only perform checks on a player's first join to the network |
| `kick-threshold` | integer | `5` | Number of failed checks before taking action |
| `kick-message` | string | `"You have been kicked for suspicious behavior. Please try again."` | Message shown when kicking suspicious players |

### Detection Methods

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `gravity-check-enabled` | boolean | `false` | Detects clients that don't simulate gravity properly |
| `hitbox-check-enabled` | boolean | `false` | Detects clients with unusual hitbox behavior |
| `yaw-check-enabled` | boolean | `false` | Detects clients with unnatural rotation patterns |
| `client-brand-check-enabled` | boolean | `false` | Validates the client mod/brand information |
| `mini-world-check-enabled` | boolean | `true` | Creates a verification world/lobby for players |
| `connection-rate-limit-enabled` | boolean | `true` | Limits connections per IP address |
| `username-pattern-check-enabled` | boolean | `true` | Detects bot-like usernames |
| `dns-check-enabled` | boolean | `false` | Performs reverse DNS lookups on connecting IPs |
| `latency-check-enabled` | boolean | `false` | Detects clients with unusual ping patterns |

### Mini-World Verification

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `mini-world-duration` | integer | `10` | How long (in seconds) players have to complete verification |
| `mini-world-min-movements` | integer | `3` | Minimum number of movements required |
| `mini-world-min-distance` | double | `2.0` | Minimum distance (in blocks) players must move |

### Connection Rate Limiting

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `connection-rate-limit` | integer | `3` | Maximum connections allowed per IP |
| `connection-rate-window-ms` | integer | `5000` | Time window for rate limiting (milliseconds) |
| `throttle-duration-ms` | integer | `15000` | How long to throttle after exceeding limits |

### Latency Checking

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `min-latency-ms` | integer | `50` | Minimum expected latency (milliseconds) |
| `max-latency-ms` | integer | `500` | Maximum expected latency (milliseconds) |

### Client Brand Validation

| Setting | Type | Array | Default |
|---------|------|-------|---------|
| `allowed-brands` | string[] | `["vanilla", "fabric", "forge", "quilt", "optifine"]` | List of allowed client brands |

## Layer 4 Protection (`[layer4-protection]`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable Layer 4 DDoS protection |
| `max-connections-per-ip` | integer | `3` | Maximum TCP connections per IP address |
| `max-packets-per-second` | integer | `100` | Maximum packets per second per IP |
| `rate-limit-window-ms` | integer | `1000` | Rate limiting time window |
| `block-duration-ms` | integer | `300000` | How long to block suspicious IPs (5 minutes) |
| `advanced-logging-enabled` | boolean | `true` | Enable detailed lobby check logging |

## Layer 7 Protection (`[layer7-protection]`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable Layer 7 protection |
| `max-login-attempts` | integer | `5` | Maximum login attempts per IP per minute |
| `login-block-duration-ms` | integer | `60000` | Block duration for excessive login attempts |
| `max-packets-per-second-authed` | integer | `200` | Packet limit for authenticated players |
| `max-packets-per-second-unauthed` | integer | `50` | Packet limit for unauthenticated players |
| `packet-size-validation` | boolean | `true` | Enable packet size validation |
| `max-packet-size` | integer | `32768` | Maximum allowed packet size (32KB) |

## Configuration Examples

### Conservative Settings (Minimal False Positives)
```toml
[antibot]
enabled = true
kick-enabled = false
mini-world-check-enabled = true
connection-rate-limit-enabled = true
username-pattern-check-enabled = true
kick-threshold = 8
mini-world-duration = 8
connection-rate-limit = 5
```

### Balanced Settings (Recommended)
```toml
[antibot]
enabled = true
kick-enabled = true
mini-world-check-enabled = true
connection-rate-limit-enabled = true
username-pattern-check-enabled = true
client-brand-check-enabled = true
kick-threshold = 5
mini-world-duration = 10
connection-rate-limit = 3
```

### Aggressive Settings (Maximum Protection)
```toml
[antibot]
enabled = true
kick-enabled = true
gravity-check-enabled = true
hitbox-check-enabled = true
yaw-check-enabled = true
client-brand-check-enabled = true
mini-world-check-enabled = true
connection-rate-limit-enabled = true
username-pattern-check-enabled = true
dns-check-enabled = true
latency-check-enabled = true
kick-threshold = 2
mini-world-duration = 20
mini-world-min-movements = 8
mini-world-min-distance = 5.0
connection-rate-limit = 1
```

## Commands

### `/antibot` Command
- `/antibot status` - Show current system status
- `/antibot stats` - Display detailed statistics
- `/antibot reload` - Reload configuration
- `/antibot kick <player>` - Manually kick a player
- `/antibot whitelist <player>` - Add player to whitelist
- `/antibot sessions` - Show active verification sessions

## Logging

The AntiBot system provides comprehensive logging:

- **INFO**: General system status and successful verifications
- **WARN**: Suspicious behavior detected
- **ERROR**: Critical issues and blocked threats
- **DEBUG**: Detailed analysis for troubleshooting
- **TRACE**: Packet-level analysis (very verbose)

## Performance Considerations

1. **DNS Checks**: Can add latency, disable for high-traffic servers
2. **Gravity/Hitbox Checks**: CPU intensive, use sparingly
3. **Mini-World Check**: Safest and most effective method
4. **Connection Rate Limiting**: Very efficient, recommended for all servers

## Recommended Settings by Server Type

### Large Public Server (1000+ players)
- Enable: Mini-world, Connection rate limiting, Username patterns
- Disable: DNS checks, Gravity checks, Hitbox checks
- Kick threshold: 3-5

### Medium Server (100-1000 players)
- Enable: All basic checks, Client brand checking
- Optional: DNS checks (if performance allows)
- Kick threshold: 3-4

### Small Private Server (<100 players)
- Enable: All checks for maximum protection
- Kick threshold: 2-3

## Troubleshooting

### False Positives
- Increase `kick-threshold`
- Increase `mini-world-duration`
- Disable intensive checks (gravity, hitbox, yaw)
- Add legitimate clients to `allowed-brands`

### Too Many Bots Getting Through
- Decrease `kick-threshold`
- Enable more detection methods
- Decrease `connection-rate-limit`
- Increase `mini-world-min-movements` and `mini-world-min-distance`

### Performance Issues
- Disable `dns-check-enabled`
- Disable `gravity-check-enabled`, `hitbox-check-enabled`, `yaw-check-enabled`
- Increase rate limiting windows
- Reduce logging verbosity
