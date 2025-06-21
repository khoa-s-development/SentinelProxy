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
 * Current Date and Time (UTC): 2025-06-14 02:09:20
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.velocitypowered.api.event.connection.ConnectionHandshakeEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.protocol.MinecraftPacket;
import com.velocitypowered.proxy.protocol.StateRegistry;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;

import java.net.InetAddress;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import java.net.InetSocketAddress;

public class PacketFilterManager {
    private static final Logger logger = LogManager.getLogger(PacketFilterManager.class);

    // Core components
    private final VelocityServer server;
    private final ExecutorService filterExecutor;
    private final ScheduledExecutorService maintenanceExecutor;

    // Packet filtering
    private final Map<String, Pattern> packetPatterns;
    private final Set<Integer> blockedPacketIds;
    private final Map<StateRegistry, Set<Class<? extends MinecraftPacket>>> filteredPackets;
    
    // Rate limiting
    private final Cache<InetAddress, RateLimit> rateLimits;
    private final Cache<UUID, PlayerPacketStats> playerStats;
    
    // Configuration
    private final int maxPacketSize;
    private final int rateLimit;
    private final int burstLimit;
    private final Duration rateLimitWindow;
    private final boolean filterEnabled;

    public PacketFilterManager(VelocityServer server) {
        this.server = server;

        // Initialize executors
        this.filterExecutor = new ThreadPoolExecutor(
            2, 
            4,
            60L, 
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(),
            new ThreadFactoryBuilder()
                .setNameFormat("packet-filter-%d")
                .setDaemon(true)
                .build()
        );

        this.maintenanceExecutor = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactoryBuilder()
                .setNameFormat("packet-maintenance")
                .setDaemon(true)
                .build()
        );

        // Initialize collections
        this.packetPatterns = new ConcurrentHashMap<>();
        this.blockedPacketIds = Collections.newSetFromMap(new ConcurrentHashMap<>());
        this.filteredPackets = new EnumMap<>(StateRegistry.class);
        
        // Initialize caches
        this.rateLimits = CacheBuilder.newBuilder()
            .expireAfterAccess(1, TimeUnit.MINUTES)
            .build();
            
        this.playerStats = CacheBuilder.newBuilder()
            .expireAfterAccess(5, TimeUnit.MINUTES)
            .build();

        // Load configuration
        this.maxPacketSize = 2097152; // 2MB
        this.rateLimit = 1000; // packets per second
        this.burstLimit = 100; // burst packets
        this.rateLimitWindow = Duration.ofSeconds(1);
        this.filterEnabled = true;

        // Initialize default filters
        initializeDefaultFilters();
        
        // Start maintenance tasks
        startMaintenanceTasks();
    }

    public boolean filterPacket(ChannelHandlerContext ctx, Object packet) {
        if (!filterEnabled) {
            return true;
        }

        try {
            // Basic validation
            if (!validatePacket(ctx, packet)) {
                return false;
            }

            // Rate limiting
            if (!checkRateLimit(ctx)) {
                return false;
            }

            // Content filtering
            if (packet instanceof MinecraftPacket) {
                return filterMinecraftPacket(ctx, (MinecraftPacket) packet);
            }

            return true;
        } catch (Exception e) {
            logger.error("Error filtering packet", e);
            return false;
        }
    }

    private boolean validatePacket(ChannelHandlerContext ctx, Object packet) {
        // Check packet size
        if (packet instanceof ByteBuf) {
            ByteBuf buf = (ByteBuf) packet;
            if (buf.readableBytes() > maxPacketSize) {
                logger.warn("Packet from {} exceeded size limit", ctx.channel().remoteAddress());
                return false;
            }
        }

        // Check packet type
        if (packet instanceof MinecraftPacket) {
            MinecraftPacket mcPacket = (MinecraftPacket) packet;
            if (blockedPacketIds.contains(mcPacket.getClass().hashCode())) {
                logger.warn("Blocked packet type from {}", ctx.channel().remoteAddress());
                return false;
            }
        }

        return true;
    }

    private boolean checkRateLimit(ChannelHandlerContext ctx) {
        InetAddress address = ((InetSocketAddress) ctx.channel().remoteAddress()).getAddress();
        RateLimit limit = rateLimits.getIfPresent(address);
        
        if (limit == null) {
            limit = new RateLimit(rateLimit, burstLimit, rateLimitWindow);
            rateLimits.put(address, limit);
        }

        return limit.tryAcquire();
    }

    private boolean filterMinecraftPacket(ChannelHandlerContext ctx, MinecraftPacket packet) {
        // Get current protocol state
        StateRegistry state = getCurrentState(ctx);
        if (state == null) {
            return true;
        }

        // Check if packet type is filtered
        Set<Class<? extends MinecraftPacket>> filtered = filteredPackets.get(state);
        if (filtered != null && filtered.contains(packet.getClass())) {
            return false;
        }

        // Pattern matching
        String content = packet.toString();
        for (Pattern pattern : packetPatterns.values()) {
            if (pattern.matcher(content).find()) {
                logger.warn("Packet from {} matched blocked pattern", ctx.channel().remoteAddress());
                return false;
            }
        }

        return true;
    }

    private StateRegistry getCurrentState(ChannelHandlerContext ctx) {
        // Implementation to get current protocol state
        return null;
    }

    private void initializeDefaultFilters() {
        // Add default packet patterns
        packetPatterns.put("sql_injection", Pattern.compile("(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)"));
        packetPatterns.put("script_injection", Pattern.compile("<script|javascript:|data:text/html"));
        
        // Block potentially dangerous packet types
        blockedPacketIds.add(/* packet ids */);
        
        // Initialize state-specific filters
        for (StateRegistry state : StateRegistry.values()) {
            filteredPackets.put(state, new HashSet<>());
        }
    }

    private void startMaintenanceTasks() {
        // Clean caches periodically
        maintenanceExecutor.scheduleAtFixedRate(() -> {
            try {
                cleanupCaches();
                logStats();
            } catch (Exception e) {
                logger.error("Error in maintenance task", e);
            }
        }, 5, 5, TimeUnit.MINUTES);
    }

    private void cleanupCaches() {
        rateLimits.cleanUp();
        playerStats.cleanUp();
    }

    private void logStats() {
        if (logger.isDebugEnabled()) {
            logger.debug("Packet filter stats - Rate limits: {}, Player stats: {}",
                rateLimits.size(), playerStats.size());
        }
    }

    // Inner classes
    private static class RateLimit {
        private final Queue<Long> timestamps;
        private final int limit;
        private final int burst;
        private final long windowMs;
        private final AtomicInteger currentBurst;

        public RateLimit(int limit, int burst, Duration window) {
            this.timestamps = new ConcurrentLinkedQueue<>();
            this.limit = limit;
            this.burst = burst;
            this.windowMs = window.toMillis();
            this.currentBurst = new AtomicInteger();
        }

        public boolean tryAcquire() {
            long now = System.currentTimeMillis();
            
            // Clean old timestamps
            while (!timestamps.isEmpty() && timestamps.peek() < now - windowMs) {
                timestamps.poll();
            }

            // Check rate limit
            if (timestamps.size() >= limit) {
                // Check burst allowance
                if (currentBurst.get() < burst) {
                    currentBurst.incrementAndGet();
                    timestamps.offer(now);
                    return true;
                }
                return false;
            }

            // Reset burst if under limit
            currentBurst.set(0);
            timestamps.offer(now);
            return true;
        }
    }

    private static class PlayerPacketStats {
        private final UUID playerId;
        private final Map<Class<? extends MinecraftPacket>, AtomicInteger> packetCounts;
        private final long startTime;

        public PlayerPacketStats(UUID playerId) {
            this.playerId = playerId;
            this.packetCounts = new ConcurrentHashMap<>();
            this.startTime = System.currentTimeMillis();
        }

        public void recordPacket(Class<? extends MinecraftPacket> packetClass) {
            packetCounts.computeIfAbsent(packetClass, k -> new AtomicInteger())
                .incrementAndGet();
        }

        public Map<Class<? extends MinecraftPacket>, Integer> getStats() {
            Map<Class<? extends MinecraftPacket>, Integer> stats = new HashMap<>();
            packetCounts.forEach((k, v) -> stats.put(k, v.get()));
            return stats;
        }
    }
}