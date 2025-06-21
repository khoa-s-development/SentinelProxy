/*
 * Copyright (C) 2018-2023 Velocity Contributors
 *
 * Current Date and Time (UTC - YYYY-MM-DD HH:MM:SS formatted): 2025-06-15 13:58:52
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security.rules;

import com.velocitypowered.api.event.connection.ConnectionHandshakeEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.security.*;
import com.velocitypowered.api.proxy.security.rules.*;
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
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
public class SecurityRuleEngine {
    private static final Logger logger = LogManager.getLogger(SecurityRuleEngine.class);

    // Rule Collections 
    private final List<SecurityRule<ConnectionContext>> connectionRules;
    private final List<SecurityRule<PacketContext>> packetRules;
    private final List<SecurityRule<PlayerContext>> playerRules;
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
        this.connectionRules = new ArrayList<>();
        this.packetRules = new ArrayList<>();
        this.playerRules = new ArrayList<>();
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
        
        logger.info("SecurityRuleEngine initialized with security level: {}", securityLevel);
    }

    private void loadDefaultRules() {
        // Connection rules
        addConnectionRule(new ConnectionRule("rate-limit")
            .condition(ctx -> checkRateLimit(ctx.getAddress()))
            .action(ctx -> {
                logger.warn("Rate limit exceeded for {}", ctx.getAddress());
                ctx.deny("Connection rate limit exceeded");
            }));

        addConnectionRule(new ConnectionRule("protocol-check")
            .condition(ctx -> isProtocolAllowed(ctx.getProtocolVersion()))
            .action(ctx -> {
                logger.warn("Blocked protocol {} from {}", ctx.getProtocolVersion(), ctx.getAddress());
                ctx.deny("Protocol version not allowed");
            }));

        // Packet rules
        addPacketRule(new PacketRule("size-check")
            .condition(ctx -> ctx.getPacketSize() <= getMaxPacketSize())
            .action(ctx -> {
                logger.warn("Oversized packet ({} bytes) from {}", ctx.getPacketSize(), ctx.getAddress());
                ctx.drop("Packet too large");
            }));

        addPacketRule(new PacketRule("pattern-check")
            .condition(ctx -> !matchesBlockedPattern(ctx.getContent()))
            .action(ctx -> {
                logger.warn("Blocked packet pattern from {}", ctx.getAddress());
                ctx.drop("Matched blocked pattern");
            }));

        // Player rules
        addPlayerRule(new PlayerRule("auth-check")
            .condition(this::isPlayerAuthenticated)
            .action(player -> {
                logger.warn("Failed authentication for player {}", player.getUsername());
                player.disconnect("Authentication required");
            }));

        logger.info("Loaded default security rules");
    }

    // Rule Management
    public void addConnectionRule(SecurityRule rule) {
        connectionRules.add(rule);
        logger.debug("Added connection rule: {}", rule.getName());
    }

    public void addPacketRule(SecurityRule rule) {
        packetRules.add(rule);
        logger.debug("Added packet rule: {}", rule.getName());
    }

    public void addPlayerRule(SecurityRule rule) {
        playerRules.add(rule);
        logger.debug("Added player rule: {}", rule.getName());
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
                logger.error("Error evaluating connection rule: {}", rule.getName(), e);
                return false;
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
                logger.error("Error evaluating packet rule: {}", rule.getName(), e);
                return false;
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
                logger.error("Error evaluating player rule: {}", rule.getName(), e);
                return false;
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
            // Additional actions could be implemented here
        }
    }

    private void handlePlayerViolation(UUID playerId, String ruleName) {
        PlayerViolationTracker tracker = playerViolationTrackers.computeIfAbsent(
            playerId, k -> new PlayerViolationTracker());
        
        tracker.recordViolation(ruleName);
        
        if (tracker.getViolationCount() >= getPlayerViolationThreshold()) {
            logger.warn("Player {} exceeded violation threshold", playerId);
            // Additional actions could be implemented here
        }
    }
    public static class ConnectionContext {
        private final ConnectionHandshakeEvent event;
        private String denyReason;

        public ConnectionContext(ConnectionHandshakeEvent event) {
            this.event = event;
        }

        public InetAddress getAddress() {
            return event.getConnection().getRemoteAddress().getAddress();
        }

        public int getProtocolVersion() {
            if (event.getHandshake() instanceof HandshakePacket) {
                return ((HandshakePacket) event.getHandshake()).getProtocolVersion();
            }
            return -1;
        }

        public void deny(String reason) {
            this.denyReason = reason;
        }

        public String getDenyReason() {
            return denyReason;
        }
    }

    public static class PacketContext {
        private final ChannelHandlerContext ctx;
        private final Object packet;
        private boolean dropped;

        public PacketContext(ChannelHandlerContext ctx, Object packet) {
            this.ctx = ctx;
            this.packet = packet;
        }

        public InetAddress getAddress() {
            return ((java.net.InetSocketAddress) ctx.channel().remoteAddress()).getAddress();
        }

        public int getPacketSize() {
            // Implement packet size calculation based on your packet structure
            return 0; // Placeholder
        }

        public String getContent() {
            return packet.toString();
        }

        public void drop(String reason) {
            this.dropped = true;
        }

        public boolean isDropped() {
            return dropped;
        }
    }

    public static class PlayerContext {
        private final Player player;
        private String disconnectReason;

        public PlayerContext(Player player) {
            this.player = player;
        }

        public Player getPlayer() {
            return player;
        }

        public UUID getPlayerId() {
            return player.getUniqueId();
        }

        public void disconnect(String reason) {
            this.disconnectReason = reason;
        }

        public String getDisconnectReason() {
            return disconnectReason;
        }
    }

    // Interface for security rules
    public interface SecurityRule {
        String getName();
        boolean evaluate(Object context);
    }

    // Base classes for specific rule types
    public static abstract class ConnectionRule implements SecurityRule {
        private final String name;
        private RuleCondition<ConnectionContext> condition;
        private RuleAction<ConnectionContext> action;

        public ConnectionRule(String name) {
            this.name = name;
        }

        public ConnectionRule condition(RuleCondition<ConnectionContext> condition) {
            this.condition = condition;
            return this;
        }

        public ConnectionRule action(RuleAction<ConnectionContext> action) {
            this.action = action;
            return this;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean evaluate(Object context) {
            if (!(context instanceof ConnectionContext)) {
                return false;
            }
            ConnectionContext ctx = (ConnectionContext) context;
            if (condition != null && !condition.test(ctx)) {
                if (action != null) {
                    action.execute(ctx);
                }
                return false;
            }
            return true;
        }
    }

    public static abstract class PacketRule implements SecurityRule {
        private final String name;
        private RuleCondition<PacketContext> condition;
        private RuleAction<PacketContext> action;

        public PacketRule(String name) {
            this.name = name;
        }

        public PacketRule condition(RuleCondition<PacketContext> condition) {
            this.condition = condition;
            return this;
        }

        public PacketRule action(RuleAction<PacketContext> action) {
            this.action = action;
            return this;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean evaluate(Object context) {
            if (!(context instanceof PacketContext)) {
                return false;
            }
            PacketContext ctx = (PacketContext) context;
            if (condition != null && !condition.test(ctx)) {
                if (action != null) {
                    action.execute(ctx);
                }
                return false;
            }
            return true;
        }
    }

    public static abstract class PlayerRule implements SecurityRule {
        private final String name;
        private RuleCondition<PlayerContext> condition;
        private RuleAction<PlayerContext> action;

        public PlayerRule(String name) {
            this.name = name;
        }

        public PlayerRule condition(RuleCondition<PlayerContext> condition) {
            this.condition = condition;
            return this;
        }

        public PlayerRule action(RuleAction<PlayerContext> action) {
            this.action = action;
            return this;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean evaluate(Object context) {
            if (!(context instanceof PlayerContext)) {
                return false;
            }
            PlayerContext ctx = (PlayerContext) context;
            if (condition != null && !condition.test(ctx)) {
                if (action != null) {
                    action.execute(ctx);
                }
                return false;
            }
            return true;
        }
    }

    // Functional interfaces for rule conditions and actions
    @FunctionalInterface
    public interface RuleCondition<T> {
        boolean test(T context);
    }

    @FunctionalInterface
    public interface RuleAction<T> {
        void execute(T context);
    }
    // Utility Methods
    private boolean checkRateLimit(InetAddress address) {
        ViolationTracker tracker = violationTrackers.get(address);
        if (tracker == null) return true;
        return tracker.getViolationCount() < getViolationThreshold();
    }

    private boolean isProtocolAllowed(int version) {
        return !blockedProtocols.contains(String.valueOf(version));
    }

    private boolean matchesBlockedPattern(String content) {
        return packetPatterns.values().stream()
            .anyMatch(pattern -> pattern.matcher(content).matches());
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
        logger.info("Security level changed to: {}", level);
    }

    private void updateRulesForSecurityLevel() {
        switch (securityLevel) {
            case LOW:
                configureForLowSecurity();
                break;
            case MEDIUM:
                configureForMediumSecurity();
                break;
            case HIGH:
                configureForHighSecurity();
                break;
            case EXTREME:
                configureForExtremeSecurity();
                break;
        }
    }

    private void configureForLowSecurity() {
        thresholds.put("max-packet-size", 4194304); // 4MB
        thresholds.put("violation-threshold", 20);
        thresholds.put("player-violation-threshold", 10);
    }

    private void configureForMediumSecurity() {
        thresholds.put("max-packet-size", 2097152); // 2MB
        thresholds.put("violation-threshold", 10);
        thresholds.put("player-violation-threshold", 5);
    }

    private void configureForHighSecurity() {
        thresholds.put("max-packet-size", 1048576); // 1MB
        thresholds.put("violation-threshold", 5);
        thresholds.put("player-violation-threshold", 3);
    }

    private void configureForExtremeSecurity() {
        thresholds.put("max-packet-size", 524288); // 512KB
        thresholds.put("violation-threshold", 3);
        thresholds.put("player-violation-threshold", 2);
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