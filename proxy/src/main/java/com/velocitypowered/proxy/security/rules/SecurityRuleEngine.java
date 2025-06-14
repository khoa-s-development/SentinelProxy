/*
 * Copyright (C) 2018-2023 Velocity Contributors
 * Current Date and Time (UTC): 2025-06-13 18:20:42
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security.rules;

import com.velocitypowered.api.event.connection.ConnectionHandshakeEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.crypto.IdentifiedKey;
import com.velocitypowered.proxy.connection.client.ConnectedPlayer;
import com.velocitypowered.proxy.protocol.packet.HandshakePacket;
import io.netty.channel.ChannelHandlerContext;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SecurityRuleEngine {
    private static final Logger logger = LogManager.getLogger(SecurityRuleEngine.class);

    // Rule Collections
    private final List<SecurityRule> connectionRules;
    private final List<SecurityRule> packetRules;
    private final List<SecurityRule> playerRules;
    private final Map<String, Pattern> packetPatterns;

    // Configuration
    private final Map<String, Integer> thresholds;
    private final Set<String> blockedProtocols;
    private SecurityLevel securityLevel;

    // Violation Tracking
    private final Map<InetAddress, ViolationTracker> violationTrackers;
    private final Map<UUID, PlayerViolationTracker> playerViolationTrackers;

    public SecurityRuleEngine() {
        // Initialize rule collections
        this.connectionRules = new CopyOnWriteArrayList<>();
        this.packetRules = new CopyOnWriteArrayList<>();
        this.playerRules = new CopyOnWriteArrayList<>();
        this.packetPatterns = new ConcurrentHashMap<>();

        // Initialize tracking
        this.violationTrackers = new ConcurrentHashMap<>();
        this.playerViolationTrackers = new ConcurrentHashMap<>();
        
        // Initialize configuration
        this.thresholds = new ConcurrentHashMap<>();
        this.blockedProtocols = Collections.newSetFromMap(new ConcurrentHashMap<>());
        this.securityLevel = SecurityLevel.MEDIUM;

        // Load default rules
        loadDefaultRules();
    }

    private void loadDefaultRules() {
        // Connection rules
        addConnectionRule(new ConnectionRule("rate-limit")
            .condition(ctx -> checkRateLimit(ctx.getAddress()))
            .action(ctx -> ctx.deny("Connection rate limit exceeded")));

        addConnectionRule(new ConnectionRule("protocol-check")
            .condition(ctx -> isProtocolAllowed(ctx.getProtocolVersion()))
            .action(ctx -> ctx.deny("Protocol version not allowed")));

        // Packet rules
        addPacketRule(new PacketRule("size-check")
            .condition(ctx -> ctx.getPacketSize() > getMaxPacketSize())
            .action(ctx -> ctx.drop("Packet too large")));

        addPacketRule(new PacketRule("pattern-check")
            .condition(ctx -> matchesBlockedPattern(ctx.getContent()))
            .action(ctx -> ctx.drop("Matched blocked pattern")));

        // Player rules
        addPlayerRule(new PlayerRule("auth-check")
            .condition(player -> !isPlayerAuthenticated(player))
            .action(player -> player.disconnect("Authentication required")));
    }

    // Rule Management
    public void addConnectionRule(SecurityRule rule) {
        connectionRules.add(rule);
    }

    public void addPacketRule(SecurityRule rule) {
        packetRules.add(rule);
    }

    public void addPlayerRule(SecurityRule rule) {
        playerRules.add(rule);
    }

    // Rule Evaluation
    public boolean validateConnection(ConnectionHandshakeEvent event) {
        ConnectionContext ctx = new ConnectionContext(event);
        
        for (SecurityRule rule : connectionRules) {
            try {
                if (!rule.evaluate(ctx)) {
                    handleViolation(ctx.getAddress(), rule.getName());
                    return false;
                }
            } catch (Exception e) {
                logger.error("Error evaluating connection rule: " + rule.getName(), e);
            }
        }
        return true;
    }

    public boolean validatePacket(ChannelHandlerContext ctx, Object packet) {
        PacketContext pctx = new PacketContext(ctx, packet);
        
        for (SecurityRule rule : packetRules) {
            try {
                if (!rule.evaluate(pctx)) {
                    handleViolation(pctx.getAddress(), rule.getName());
                    return false;
                }
            } catch (Exception e) {
                logger.error("Error evaluating packet rule: " + rule.getName(), e);
            }
        }
        return true;
    }

    public boolean validatePlayer(Player player) {
        PlayerContext ctx = new PlayerContext(player);
        
        for (SecurityRule rule : playerRules) {
            try {
                if (!rule.evaluate(ctx)) {
                    handlePlayerViolation(player.getUniqueId(), rule.getName());
                    return false;
                }
            } catch (Exception e) {
                logger.error("Error evaluating player rule: " + rule.getName(), e);
            }
        }
        return true;
    }

    // Violation Handling
    private void handleViolation(InetAddress address, String ruleName) {
        ViolationTracker tracker = violationTrackers.computeIfAbsent(
            address, k -> new ViolationTracker());
        
        tracker.recordViolation(ruleName);
        
        if (tracker.getViolationCount() >= getViolationThreshold()) {
            logger.warn("Address {} exceeded violation threshold", address);
            // Trigger additional actions (blacklist, notify, etc)
        }
    }

    private void handlePlayerViolation(UUID playerId, String ruleName) {
        PlayerViolationTracker tracker = playerViolationTrackers.computeIfAbsent(
            playerId, k -> new PlayerViolationTracker());
        
        tracker.recordViolation(ruleName);
        
        if (tracker.getViolationCount() >= getPlayerViolationThreshold()) {
            logger.warn("Player {} exceeded violation threshold", playerId);
            // Trigger additional actions
        }
    }

    // Utility Methods
    private boolean checkRateLimit(InetAddress address) {
        // Implement rate limiting logic
        return true;
    }

    private boolean isProtocolAllowed(int version) {
        return !blockedProtocols.contains(String.valueOf(version));
    }

    private boolean matchesBlockedPattern(String content) {
        for (Pattern pattern : packetPatterns.values()) {
            if (pattern.matcher(content).matches()) {
                return true;
            }
        }
        return false;
    }

    private boolean isPlayerAuthenticated(Player player) {
        if (player instanceof ConnectedPlayer) {
            ConnectedPlayer cp = (ConnectedPlayer) player;
            IdentifiedKey key = cp.getIdentifiedKey();
            return key != null && key.isValid();
        }
        return false;
    }

    private int getMaxPacketSize() {
        return thresholds.getOrDefault("max-packet-size", 2097152);
    }

    private int getViolationThreshold() {
        return thresholds.getOrDefault("violation-threshold", 10);
    }

    private int getPlayerViolationThreshold() {
        return thresholds.getOrDefault("player-violation-threshold", 5);
    }

    // Configuration
    public void setSecurityLevel(SecurityLevel level) {
        this.securityLevel = level;
        updateRulesForSecurityLevel();
    }

    private void updateRulesForSecurityLevel() {
        switch (securityLevel) {
            case LOW:
                // Configure for basic protection
                break;
            case MEDIUM:
                // Configure for standard protection
                break;
            case HIGH:
                // Configure for enhanced protection
                break;
            case EXTREME:
                // Configure for maximum protection
                break;
        }
    }

    // Inner Classes
    private static class ViolationTracker {
        private final Map<String, Integer> violations = new HashMap<>();
        private int totalViolations = 0;

        public void recordViolation(String ruleName) {
            violations.merge(ruleName, 1, Integer::sum);
            totalViolations++;
        }

        public int getViolationCount() {
            return totalViolations;
        }
    }

    private static class PlayerViolationTracker {
        private final Map<String, Integer> violations = new HashMap<>();
        private int totalViolations = 0;

        public void recordViolation(String ruleName) {
            violations.merge(ruleName, 1, Integer::sum);
            totalViolations++;
        }

        public int getViolationCount() {
            return totalViolations;
        }
    }

    public enum SecurityLevel {
        LOW,
        MEDIUM,
        HIGH,
        EXTREME
    }
}