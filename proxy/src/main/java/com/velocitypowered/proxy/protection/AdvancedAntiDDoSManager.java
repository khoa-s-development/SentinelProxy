/*
 * Copyright (C) 2018-2023 Velocity Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Current Date and Time (UTC): 2025-06-14 07:40:45
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.protocol.packet.PacketWrapper;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelFutureListener;
import com.velocitypowered.proxy.protection.ml.AIAnalyzer;
import com.velocitypowered.proxy.protection.layer4.Layer4Detector;
import com.velocitypowered.proxy.protection.layer7.Layer7Detector;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import com.google.gson.Gson;
import java.util.concurrent.TimeUnit;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import io.prometheus.client.Counter;
import io.prometheus.client.Gauge;
import io.prometheus.client.Histogram;

public class AdvancedAntiDDoSManager {
    private static final Logger logger = LogManager.getLogger(AdvancedAntiDDoSManager.class);

    // Core components
    private final VelocityServer server;
    private final ExecutorService ddosExecutor;
    private final ScheduledExecutorService maintenanceExecutor;

    // DDoS detection
    private final ConnectionAnalyzer connectionAnalyzer;
    private final PacketAnalyzer packetAnalyzer;
    private final BehaviorAnalyzer behaviorAnalyzer;

    // Protection mechanisms
    private final Map<InetAddress, ConnectionState> connectionStates;
    private final Cache<InetAddress, RateTracker> rateTrackers;
    private final Set<InetAddress> blacklist;
    private final Set<InetAddress> whitelist;

    // Configuration
    private final int connectionThreshold;
    private final int packetThreshold;
    private final int blacklistThreshold;
    private final Duration blacklistDuration;
    private final boolean autoBlacklist;
    
    // DoS Migrate
    private final Layer4Detector layer4Detector;
    private final Layer7Detector layer7Detector;
    private final AIAnalyzer aiAnalyzer;
    private final String aiApiEndpoint;
    private final OkHttpClient httpClient;
    private final Gson gson;
    

    public AdvancedAntiDDoSManager(VelocityServer server, String aiApiEndpoint) {
        this.server = server;
        this.layer4Detector = new Layer4Detector();
        this.layer7Detector = new Layer7Detector();
        this.aiAnalyzer = new AIAnalyzer();
        this.aiApiEndpoint = aiApiEndpoint;
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .writeTimeout(5, TimeUnit.SECONDS)
            .build();
            
        this.gson = new Gson();
        // Initialize executors
        this.ddosExecutor = new ThreadPoolExecutor(
            4,
            8,
            60L,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(),
            new ThreadFactoryBuilder()
                .setNameFormat("ddos-worker-%d")
                .setDaemon(true)
                .build()
        );
        // metrics
    private static final Counter ddosAttemptsTotal = Counter.build()
        .name("ddos_attempts_total")
        .help("Total number of DDoS attempts detected")
        .labelNames("type", "source")
        .register();

    private static final Gauge activeConnections = Gauge.build()
        .name("active_connections")
        .help("Number of active connections")
        .register();

    private static final Histogram packetSizeBytes = Histogram.build()
        .name("packet_size_bytes")
        .help("Distribution of packet sizes")
        .buckets(64, 128, 256, 512, 1024, 2048, 4096)
        .register();
    private enum ProtectionMode {
        LEARNING,    // Just monitor and learn patterns
        PASSIVE,     // Warn but don't block
        ACTIVE,      // Block detected threats
        AGGRESSIVE   // More strict thresholds
    }
    private ProtectionMode currentMode = ProtectionMode.ACTIVE;

        this.maintenanceExecutor = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactoryBuilder()
                .setNameFormat("ddos-maintenance")
                .setDaemon(true)
                .build()
        );
    private class DynamicThresholds {
        private volatile int connectionThreshold;
        private volatile int packetThreshold;
        private final double adjustmentFactor = 1.5;
        
        public void adjustThresholds(int detectedAttacks) {
            if (detectedAttacks > 0) {
                connectionThreshold = (int)(connectionThreshold / adjustmentFactor);
                packetThreshold = (int)(packetThreshold / adjustmentFactor);
            } else {
                connectionThreshold = (int)(connectionThreshold * adjustmentFactor);
                packetThreshold = (int)(packetThreshold * adjustmentFactor);
            }
        }
    }
    private final DynamicThresholds dynamicThresholds = new DynamicThresholds();
    private class AttackPattern {
        private final String type;
        private final InetAddress source;
        private final long timestamp;
        private final Map<String, Object> characteristics;
        
        public AttackPattern(String type, InetAddress source, Map<String, Object> chars) {
            this.type = type;
            this.source = source;
            this.timestamp = System.currentTimeMillis();
            this.characteristics = chars;
        }
    }
    private final Queue<AttackPattern> recentAttacks = new ConcurrentLinkedQueue<>();
    private void updateProtectionMode() {
        int recentAttackCount = recentAttacks.size();
        if (recentAttackCount > 100) {
            currentMode = ProtectionMode.AGGRESSIVE;
        } else if (recentAttackCount > 50) {
            currentMode = ProtectionMode.ACTIVE;
        } else if (recentAttackCount > 10) {
            currentMode = ProtectionMode.PASSIVE;
        } else {
            currentMode = ProtectionMode.LEARNING;
        }
    }
    private void recordAttackPattern(String type, InetAddress source, Map<String, Object> chars) {
        AttackPattern pattern = new AttackPattern(type, source, chars);
        recentAttacks.offer(pattern);
        
        // Keep only recent patterns
        while (recentAttacks.size() > 1000) {
            recentAttacks.poll();
        }
        
        // Update protection mode based on recent activity
        updateProtectionMode();
    }

        // Initialize analyzers
        this.connectionAnalyzer = new ConnectionAnalyzer();
        this.packetAnalyzer = new PacketAnalyzer();
        this.behaviorAnalyzer = new BehaviorAnalyzer();

        // Initialize collections
        this.connectionStates = new ConcurrentHashMap<>();
        this.rateTrackers = CacheBuilder.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .build();
        this.blacklist = Collections.newSetFromMap(new ConcurrentHashMap<>());
        this.whitelist = Collections.newSetFromMap(new ConcurrentHashMap<>());

        // Load configuration
        this.connectionThreshold = 100;
        this.packetThreshold = 1000;
        this.blacklistThreshold = 3;
        this.blacklistDuration = Duration.ofHours(24);
        this.autoBlacklist = true;

        // Start maintenance/AI tasks
        startMaintenanceTasks();
        startAIDataCollection();
    }

/**
 * Handle incoming connection request
 * @param ctx Connection context
 * @return true if connection is allowed, false otherwise
 */
public boolean handleConnection(ChannelHandlerContext ctx) {
    // Get client address
    InetSocketAddress socketAddress = (InetSocketAddress) ctx.channel().remoteAddress();
    InetAddress address = socketAddress.getAddress();
    
    try {
        // Increment active connections counter
        activeConnections.inc();
        
        // 1. First check whitelist - fastest positive check
        if (isWhitelisted(address)) {
            logger.debug("Connection allowed from whitelisted address: {}", address);
            return true;
        }

        // 2. Then check blacklist - fastest negative check  
        if (isBlacklisted(address)) {
            logger.warn("Rejected blacklisted connection from: {}", address);
            ddosAttemptsTotal.labels("blacklisted", address.getHostAddress()).inc();
            ctx.close();
            return false;
        }

        // 3. Layer 4 DDoS detection
        if (!layer4Detector.analyze(ctx)) {
            logger.warn("Layer 4 DDoS detected from: {}", address);
            ddosAttemptsTotal.labels("layer4", address.getHostAddress()).inc();
            
            // Record attack pattern
            Map<String, Object> characteristics = new HashMap<>();
            characteristics.put("port", socketAddress.getPort());
            characteristics.put("timestamp", System.currentTimeMillis());
            recordAttackPattern("layer4_ddos", address, characteristics);
            
            // Handle violation with current protection mode
            handleViolation(ctx, address, "Layer 4 DDoS detected");
            return false;
        }

        // 4. Connection rate limiting based on current mode
        ConnectionState state = connectionStates.computeIfAbsent(address, 
            k -> new ConnectionState());
        state.updateActivity();

        if (currentMode == ProtectionMode.AGGRESSIVE) {
            // Use stricter thresholds in aggressive mode
            if (state.getConnectionRate() > dynamicThresholds.connectionThreshold / 2) {
                logger.warn("Aggressive mode - Connection rate exceeded from: {}", address);
                ddosAttemptsTotal.labels("rate_limit", address.getHostAddress()).inc();
                handleViolation(ctx, address, "Connection rate exceeded (aggressive mode)");
                return false;
            }
        } else if (state.getConnectionRate() > dynamicThresholds.connectionThreshold) {
            logger.warn("Connection rate exceeded from: {}", address);
            ddosAttemptsTotal.labels("rate_limit", address.getHostAddress()).inc();
            handleViolation(ctx, address, "Connection rate exceeded");
            return false;
        }

        // Connection allowed
        if (logger.isDebugEnabled()) {
            logger.debug("New connection accepted from: {}", address);
        }
        return true;

    } catch (Exception e) {
        logger.error("Error handling connection from " + address, e);
        return false;
        
    } finally {
        if (!ctx.channel().isActive()) {
            activeConnections.dec();
        }
    }
}

/**
 * Handle incoming packet
 * @param ctx Connection context
 * @param packet The packet to analyze
 * @return true if packet is allowed, false if it should be blocked
 */
public boolean handlePacket(ChannelHandlerContext ctx, PacketWrapper packet) {
    InetSocketAddress socketAddress = (InetSocketAddress) ctx.channel().remoteAddress();
    InetAddress address = socketAddress.getAddress();
    long startTime = System.currentTimeMillis();

    try {
        // Record packet metrics
        packetSizeBytes.observe(packet.getSize());
        
        // 1. First validate packet structure and size
        if (!isValidPacket(packet)) {
            logger.warn("Invalid packet detected from {}: size={}, type={}", 
                address, packet.getSize(), packet.getClass().getSimpleName());
                
            Map<String, Object> chars = new HashMap<>();
            chars.put("size", packet.getSize());
            chars.put("type", packet.getClass().getSimpleName());
            chars.put("validation_error", true);
            recordAttackPattern("malicious_packet", address, chars);
            
            ddosAttemptsTotal.labels("invalid_packet", address.getHostAddress()).inc();
            return false;
        }

        // 2. Check rate limits - fast check before detailed analysis
        RateTracker tracker = rateTrackers.computeIfAbsent(address, k -> new RateTracker());
        if (!tracker.checkRate(packet)) {
            logger.warn("Rate limit exceeded from {}: type={}", 
                address, packet.getClass().getSimpleName());
                
            ddosAttemptsTotal.labels("rate_limit", address.getHostAddress()).inc();
            handleViolation(ctx, address, "Rate limit exceeded");
            return false;
        }

        // 3. Layer 7 DDoS detection
        if (!layer7Detector.analyze(ctx, packet)) {
            logger.warn("Layer 7 DDoS detected from {}", address);
            
            Map<String, Object> chars = new HashMap<>();
            chars.put("packet_type", packet.getClass().getSimpleName());
            chars.put("detection_time", System.currentTimeMillis());
            recordAttackPattern("layer7_ddos", address, chars);
            
            ddosAttemptsTotal.labels("layer7", address.getHostAddress()).inc();
            handleViolation(ctx, address, "Layer 7 DDoS detected");
            return false;
        }

        // 4. Detailed packet analysis
        if (!packetAnalyzer.analyzePacket(packet, ctx)) {
            logger.warn("Packet analysis failed for {} - type: {}", 
                address, packet.getClass().getSimpleName());
                
            ddosAttemptsTotal.labels("packet_analysis", address.getHostAddress()).inc();
            handleViolation(ctx, address, "Packet analysis failed");
            return false;
        }

        // 5. Behavior analysis if connection state exists
        ConnectionState state = connectionStates.get(address);
        if (state != null) {
            state.updateActivity();
            
            if (!behaviorAnalyzer.analyzeBehavior(address, state, packet)) {
                logger.warn("Suspicious behavior detected from {}", address);
                
                Map<String, Object> chars = new HashMap<>();
                chars.put("state_age", System.currentTimeMillis() - state.getCreationTime());
                chars.put("violation_count", state.getViolations());
                recordAttackPattern("suspicious_behavior", address, chars);
                
                ddosAttemptsTotal.labels("behavior", address.getHostAddress()).inc();
                handleViolation(ctx, address, "Suspicious behavior detected");
                return false;
            }
        }

        // 6. Async AI analysis
        if (currentMode != ProtectionMode.PASSIVE) {
            aiAnalyzer.analyzePacket(ctx, packet)
                .thenAcceptAsync(result -> {
                    if (result.isMalicious() && result.getConfidence() > getAiThreshold()) {
                        logger.warn("AI detected threat from {} - confidence: {}, reason: {}", 
                            address, result.getConfidence(), result.getReason());
                            
                        Map<String, Object> chars = new HashMap<>();
                        chars.put("confidence", result.getConfidence());
                        chars.put("reason", result.getReason());
                        recordAttackPattern("ai_detected", address, chars);
                        
                        ddosAttemptsTotal.labels("ai_detection", address.getHostAddress()).inc();
                        handleViolation(ctx, address, "AI detected threat: " + result.getReason());
                    }
                }, ddosExecutor)
                .exceptionally(e -> {
                    logger.error("AI analysis error for " + address, e);
                    return null;
                });
        }

        // Packet allowed
        if (logger.isDebugEnabled()) {
            long processingTime = System.currentTimeMillis() - startTime;
            logger.debug("Packet processed from {} in {}ms - type: {}", 
                address, processingTime, packet.getClass().getSimpleName());
        }
        return true;

    } catch (Exception e) {
        logger.error("Error processing packet from " + address, e);
        return false;
    }
}

/**
 * Get AI confidence threshold based on current protection mode
 */
private double getAiThreshold() {
    switch (currentMode) {
        case AGGRESSIVE: return 0.7;
        case ACTIVE: return 0.8;
        case PASSIVE: return 0.9;
        default: return 0.95;
    }
}

    private void handleViolation(ChannelHandlerContext ctx, InetAddress address, String reason) {
        ConnectionState state = connectionStates.get(address);
        if (state != null) {
            state.incrementViolations();
            
            if (autoBlacklist && state.getViolations() >= blacklistThreshold) {
                blacklist(address, reason);
            }
        }

        logger.warn("DDoS protection violation from {}: {}", address, reason);
        ctx.close();
    }

    public void blacklist(InetAddress address, String reason) {
        if (!blacklist.contains(address)) {
            blacklist.add(address);
            logger.info("Blacklisted {} for DDoS protection: {}", address, reason);

            // Schedule removal
            maintenanceExecutor.schedule(() -> {
                blacklist.remove(address);
                logger.info("Removed {} from DDoS protection blacklist", address);
            }, blacklistDuration.toMillis(), TimeUnit.MILLISECONDS);
        }
    }

    public void whitelist(InetAddress address) {
        whitelist.add(address);
        blacklist.remove(address);
        logger.info("Whitelisted {} for DDoS protection", address);
    }

    private boolean isBlacklisted(InetAddress address) {
        return blacklist.contains(address);
    }

    private boolean isWhitelisted(InetAddress address) {
        return whitelist.contains(address);
    }

    private void startMaintenanceTasks() {
        maintenanceExecutor.scheduleAtFixedRate(() -> {
            try {
                cleanup();
                logStats();
            } catch (Exception e) {
                logger.error("Error in maintenance task", e);
            }
        }, 5, 5, TimeUnit.MINUTES);
    }

    private void cleanup() {
        connectionStates.entrySet().removeIf(entry -> 
            !entry.getValue().hasRecentActivity());
        rateTrackers.cleanUp();
    }

    private void logStats() {
        if (logger.isDebugEnabled()) {
            logger.debug("DDoS protection stats - Connections: {}, Blacklisted: {}, Whitelisted: {}",
                connectionStates.size(), blacklist.size(), whitelist.size());
        }
    }

    private static class ConnectionState {
        private final AtomicInteger violations = new AtomicInteger();
        private volatile long lastActivity = System.currentTimeMillis();
        private final Map<String, Object> attributes = new ConcurrentHashMap<>();

        public void incrementViolations() {
            violations.incrementAndGet();
        }

        public int getViolations() {
            return violations.get();
        }

        public void updateActivity() {
            lastActivity = System.currentTimeMillis();
        }

        public boolean hasRecentActivity() {
            return System.currentTimeMillis() - lastActivity < TimeUnit.MINUTES.toMillis(30);
        }

        public void setAttribute(String key, Object value) {
            attributes.put(key, value);
        }

        public Object getAttribute(String key) {
            return attributes.get(key);
        }
    }

    private static class RateTracker {
        private final Map<Class<?>, Queue<Long>> packetTimestamps = new ConcurrentHashMap<>();
        private final AtomicInteger totalPackets = new AtomicInteger();
        private static final int WINDOW_SIZE = 1000; // 1 second
        private static final int MAX_PACKETS_PER_SECOND = 1000;

        public boolean checkRate(PacketWrapper packet) {
            long now = System.currentTimeMillis();
            Class<?> packetClass = packet.getClass();

            Queue<Long> timestamps = packetTimestamps.computeIfAbsent(packetClass,
                k -> new ConcurrentLinkedQueue<>());

            // Clean old timestamps
            while (!timestamps.isEmpty() && timestamps.peek() < now - WINDOW_SIZE) {
                timestamps.poll();
                totalPackets.decrementAndGet();
            }

            // Check rate
            if (timestamps.size() >= MAX_PACKETS_PER_SECOND || 
                totalPackets.get() >= MAX_PACKETS_PER_SECOND) {
                return false;
            }

            // Record packet
            timestamps.offer(now);
            totalPackets.incrementAndGet();
            return true;
        }
    }

    private static class ConnectionAnalyzer {
        public boolean analyzeConnection(InetAddress address, ConnectionState state) {
            // Implement connection analysis logic
            return true;
        }
    }

    private static class PacketAnalyzer {
        public boolean analyzePacket(PacketWrapper packet, ChannelHandlerContext ctx) {
            // Implement packet analysis logic
            return true;
        }
    }

    private static class BehaviorAnalyzer {
        public boolean analyzeBehavior(InetAddress address, ConnectionState state, 
                PacketWrapper packet) {
            // Implement behavior analysis logic
            return true;
        }
    }
        public Map<String, Object> getAttackStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("total_attacks", ddosAttemptsTotal.get());
        stats.put("active_connections", activeConnections.get());
        stats.put("current_mode", currentMode);
        stats.put("recent_attacks", recentAttacks.size());
        return stats;
    }
        public void updateConfiguration(Map<String, Object> config) {
        if (config.containsKey("mode")) {
            currentMode = ProtectionMode.valueOf((String) config.get("mode"));
        }
        if (config.containsKey("connectionThreshold")) {
            dynamicThresholds.connectionThreshold = (int) config.get("connectionThreshold");
        }
        if (config.containsKey("packetThreshold")) {
            dynamicThresholds.packetThreshold = (int) config.get("packetThreshold");
        }
    }
}