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
 * Current Date and Time (UTC): 2025-06-14 08:49:25
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.state;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.velocitypowered.proxy.protocol.packet.PacketWrapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Map;
import java.util.HashMap;

public class ConnectionState {
    private static final Logger logger = LogManager.getLogger(ConnectionState.class);

    // State tracking
    private final AtomicInteger violations;
    private final AtomicInteger connectionsPerSecond;
    private final AtomicInteger packetsPerSecond;
    private final AtomicLong bytesTransferred;
    private final AtomicLong lastActivity;
    private final AtomicLong creationTime;

    // Connection metrics
    private final Queue<Long> connectionTimestamps;
    private final Map<Class<?>, PacketMetrics> packetMetrics;
    private final Cache<String, RateLimiter> rateLimiters;

    // Statistics
    private final StatisticsCollector statistics;

    // Configuration
    private final int maxViolations;
    private final int rateWindowSeconds;
    private final int maxConnectionsPerSecond;
    private final int maxPacketsPerSecond;
    private final long maxBytesPerSecond;

    public ConnectionState() {
        // Initialize counters
        this.violations = new AtomicInteger();
        this.connectionsPerSecond = new AtomicInteger();
        this.packetsPerSecond = new AtomicInteger();
        this.bytesTransferred = new AtomicLong();
        this.lastActivity = new AtomicLong(System.currentTimeMillis());
        this.creationTime = new AtomicLong(System.currentTimeMillis());

        // Initialize collections
        this.connectionTimestamps = new ConcurrentLinkedQueue<>();
        this.packetMetrics = new ConcurrentHashMap<>();
        this.rateLimiters = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.MINUTES)
            .build();

        // Initialize statistics
        this.statistics = new StatisticsCollector();

        // Load configuration
        this.maxViolations = 3;
        this.rateWindowSeconds = 1;
        this.maxConnectionsPerSecond = 10;
        this.maxPacketsPerSecond = 100;
        this.maxBytesPerSecond = 1024 * 1024; // 1MB

        // Start maintenance tasks
        startMaintenanceTasks();
    }

    public void recordConnection() {
        long now = System.currentTimeMillis();
        connectionTimestamps.offer(now);
        connectionsPerSecond.incrementAndGet();
        updateLastActivity();

        // Clean old timestamps
        cleanOldTimestamps(now);
    }

    public void recordPacket(PacketWrapper packet) {
        long now = System.currentTimeMillis();
        packetsPerSecond.incrementAndGet();
        bytesTransferred.addAndGet(packet.getSize());
        updateLastActivity();

        // Update packet metrics
        PacketMetrics metrics = packetMetrics.computeIfAbsent(
            packet.getClass(),
            k -> new PacketMetrics()
        );
        metrics.recordPacket(packet);

        // Update statistics
        statistics.recordPacket(packet);
    }

    public boolean isRateLimited(String action) {
        try {
            RateLimiter limiter = rateLimiters.get(action, () -> new RateLimiter(maxConnectionsPerSecond));
            return !limiter.tryAcquire();
        } catch (ExecutionException e) {
            logger.error("Error checking rate limit for " + action, e);
            return false;
        }
    }

    public void incrementViolations() {
        violations.incrementAndGet();
    }

    public boolean hasExceededViolations() {
        return violations.get() >= maxViolations;
    }

    public boolean hasRecentActivity() {
        return System.currentTimeMillis() - lastActivity.get() < Duration.ofMinutes(30).toMillis();
    }

    public double getConnectionRate() {
        cleanOldTimestamps(System.currentTimeMillis());
        return connectionTimestamps.size() / (double) rateWindowSeconds;
    }

    private void updateLastActivity() {
        lastActivity.set(System.currentTimeMillis());
    }

    private void cleanOldTimestamps(long now) {
        while (!connectionTimestamps.isEmpty() && 
               now - connectionTimestamps.peek() > rateWindowSeconds * 1000) {
            connectionTimestamps.poll();
            connectionsPerSecond.decrementAndGet();
        }
    }

    private void startMaintenanceTasks() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactoryBuilder()
                .setNameFormat("connection-state-maintenance-%d")
                .setDaemon(true)
                .build()
        );

        // Reset counters periodically
        executor.scheduleAtFixedRate(() -> {
            packetsPerSecond.set(0);
            bytesTransferred.set(0);
        }, 1, 1, TimeUnit.SECONDS);

        // Clean up old metrics
        executor.scheduleAtFixedRate(() -> {
            try {
                cleanupOldMetrics();
            } catch (Exception e) {
                logger.error("Error cleaning up metrics", e);
            }
        }, 5, 5, TimeUnit.MINUTES);
    }

    private void cleanupOldMetrics() {
        long cutoff = System.currentTimeMillis() - Duration.ofMinutes(5).toMillis();
        packetMetrics.values().removeIf(metrics -> metrics.getLastUpdate() < cutoff);
    }

    private static class PacketMetrics {
        private final AtomicInteger count;
        private final AtomicLong totalBytes;
        private volatile long lastUpdate;

        public PacketMetrics() {
            this.count = new AtomicInteger();
            this.totalBytes = new AtomicLong();
            this.lastUpdate = System.currentTimeMillis();
        }

        public void recordPacket(PacketWrapper packet) {
            count.incrementAndGet();
            totalBytes.addAndGet(packet.getSize());
            lastUpdate = System.currentTimeMillis();
        }

        public long getLastUpdate() {
            return lastUpdate;
        }
    }

    private static class RateLimiter {
        private final int permitsPerSecond;
        private final Queue<Long> timestamps;

        public RateLimiter(int permitsPerSecond) {
            this.permitsPerSecond = permitsPerSecond;
            this.timestamps = new ConcurrentLinkedQueue<>();
        }

        public boolean tryAcquire() {
            long now = System.currentTimeMillis();
            
            // Remove expired timestamps
            while (!timestamps.isEmpty() && now - timestamps.peek() > 1000) {
                timestamps.poll();
            }

            // Check if under limit
            if (timestamps.size() < permitsPerSecond) {
                timestamps.offer(now);
                return true;
            }

            return false;
        }
    }

    private static class StatisticsCollector {
        private final Map<String, AtomicInteger> packetTypeCount;
        private final AtomicLong totalBytesProcessed;
        private final Queue<Double> rateHistory;
        private final int historySize = 60; // Keep 1 minute of history

        public StatisticsCollector() {
            this.packetTypeCount = new ConcurrentHashMap<>();
            this.totalBytesProcessed = new AtomicLong();
            this.rateHistory = new ConcurrentLinkedQueue<>();
        }

        public void recordPacket(PacketWrapper packet) {
            String type = packet.getClass().getSimpleName();
            packetTypeCount.computeIfAbsent(type, k -> new AtomicInteger()).incrementAndGet();
            totalBytesProcessed.addAndGet(packet.getSize());

            // Update rate history
            if (rateHistory.size() >= historySize) {
                rateHistory.poll();
            }
            rateHistory.offer((double) packet.getSize());
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("violations", violations.get());
        stats.put("connections_per_second", connectionsPerSecond.get());
        stats.put("packets_per_second", packetsPerSecond.get());
        stats.put("bytes_transferred", bytesTransferred.get());
        stats.put("uptime_seconds", (System.currentTimeMillis() - creationTime.get()) / 1000);
        stats.put("last_activity", lastActivity.get());

        Map<String, Integer> packetStats = new HashMap<>();
        packetMetrics.forEach((type, metrics) -> 
            packetStats.put(type.getSimpleName(), metrics.count.get()));
        stats.put("packet_counts", packetStats);

        return stats;
    }

    public long getCreationTime() {
        return creationTime.get();
    }

    public int getViolations() {
        return violations.get();
    }
    public enum ConnectionState {
    HANDSHAKE,
    STATUS,
    LOGIN,
    PLAY
}
}