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
 * Current Date and Time (UTC): 2025-06-14 08:52:18
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.rate;

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

public class RateTracker {
    private static final Logger logger = LogManager.getLogger(RateTracker.class);

    // Rate tracking components
    private final SlidingWindowCounter packetCounter;
    private final TokenBucket bandwidthLimiter;
    private final LeakyBucket requestLimiter;
    private final AdaptiveRateLimiter adaptiveLimiter;

    // Data tracking
    private final Map<Class<?>, PacketStats> packetStats;
    private final Queue<RateSnapshot> rateHistory;
    private final Cache<String, AtomicInteger> burstTracking;

    // Configuration
    private final int maxPacketsPerSecond;
    private final long maxBytesPerSecond;
    private final int maxRequestsPerSecond;
    private final Duration windowSize;
    private final int historySize;

    public RateTracker() {
        // Initialize rate limiters
        this.packetCounter = new SlidingWindowCounter(Duration.ofSeconds(1));
        this.bandwidthLimiter = new TokenBucket(1024 * 1024, 1024); // 1MB/s, 1KB tokens
        this.requestLimiter = new LeakyBucket(100); // 100 requests/s
        this.adaptiveLimiter = new AdaptiveRateLimiter();

        // Initialize collections
        this.packetStats = new ConcurrentHashMap<>();
        this.rateHistory = new ConcurrentLinkedQueue<>();
        this.burstTracking = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.MINUTES)
            .build();

        // Load configuration
        this.maxPacketsPerSecond = 1000;
        this.maxBytesPerSecond = 1024 * 1024; // 1MB
        this.maxRequestsPerSecond = 100;
        this.windowSize = Duration.ofSeconds(1);
        this.historySize = 60; // 1 minute history

        // Start maintenance tasks
        startMaintenanceTasks();
    }

    public boolean checkRate(PacketWrapper packet) {
        try {
            long now = System.currentTimeMillis();
            
            // Update packet stats
            PacketStats stats = packetStats.computeIfAbsent(
                packet.getClass(),
                k -> new PacketStats()
            );
            stats.recordPacket(packet);

            // Check packet rate
            if (!packetCounter.tryIncrement()) {
                logger.warn("Packet rate exceeded: {}/s", maxPacketsPerSecond);
                return false;
            }

            // Check bandwidth
            if (!bandwidthLimiter.tryConsume(packet.getSize())) {
                logger.warn("Bandwidth limit exceeded: {} bytes/s", maxBytesPerSecond);
                return false;
            }

            // Check request rate
            if (!requestLimiter.tryAcquire()) {
                logger.warn("Request rate exceeded: {}/s", maxRequestsPerSecond);
                return false;
            }

            // Check adaptive rate
            if (!adaptiveLimiter.checkRate(packet)) {
                logger.warn("Adaptive rate limit exceeded");
                return false;
            }

            // Update rate history
            updateRateHistory(now, packet);

            return true;

        } catch (Exception e) {
            logger.error("Error checking rate", e);
            return false;
        }
    }

    private void updateRateHistory(long timestamp, PacketWrapper packet) {
        RateSnapshot snapshot = new RateSnapshot(
            timestamp,
            packetCounter.getCount(),
            bandwidthLimiter.getCurrentRate(),
            requestLimiter.getCurrentRate()
        );

        rateHistory.offer(snapshot);

        // Maintain history size
        while (rateHistory.size() > historySize) {
            rateHistory.poll();
        }
    }

    private void startMaintenanceTasks() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactoryBuilder()
                .setNameFormat("rate-tracker-maintenance-%d")
                .setDaemon(true)
                .build()
        );

        // Clean up old stats
        executor.scheduleAtFixedRate(() -> {
            try {
                cleanupOldStats();
            } catch (Exception e) {
                logger.error("Error cleaning up stats", e);
            }
        }, 1, 1, TimeUnit.MINUTES);

        // Update adaptive limits
        executor.scheduleAtFixedRate(() -> {
            try {
                adaptiveLimiter.updateLimits(getRateHistory());
            } catch (Exception e) {
                logger.error("Error updating adaptive limits", e);
            }
        }, 5, 5, TimeUnit.SECONDS);
    }

    private void cleanupOldStats() {
        long cutoff = System.currentTimeMillis() - Duration.ofMinutes(5).toMillis();
        packetStats.values().removeIf(stats -> stats.getLastUpdate() < cutoff);
    }

    private static class PacketStats {
        private final AtomicInteger count;
        private final AtomicLong bytes;
        private volatile long lastUpdate;

        public PacketStats() {
            this.count = new AtomicInteger();
            this.bytes = new AtomicLong();
            this.lastUpdate = System.currentTimeMillis();
        }

        public void recordPacket(PacketWrapper packet) {
            count.incrementAndGet();
            bytes.addAndGet(packet.getSize());
            lastUpdate = System.currentTimeMillis();
        }

        public long getLastUpdate() {
            return lastUpdate;
        }
    }

    private static class RateSnapshot {
        private final long timestamp;
        private final int packetRate;
        private final long byteRate;
        private final int requestRate;

        public RateSnapshot(long timestamp, int packetRate, long byteRate, int requestRate) {
            this.timestamp = timestamp;
            this.packetRate = packetRate;
            this.byteRate = byteRate;
            this.requestRate = requestRate;
        }
    }

    private static class SlidingWindowCounter {
        private final Queue<Long> timestamps;
        private final Duration window;

        public SlidingWindowCounter(Duration window) {
            this.timestamps = new ConcurrentLinkedQueue<>();
            this.window = window;
        }

        public boolean tryIncrement() {
            long now = System.currentTimeMillis();
            cleanOldTimestamps(now);
            
            if (timestamps.size() < maxPacketsPerSecond) {
                timestamps.offer(now);
                return true;
            }
            return false;
        }

        private void cleanOldTimestamps(long now) {
            while (!timestamps.isEmpty() && 
                   now - timestamps.peek() > window.toMillis()) {
                timestamps.poll();
            }
        }

        public int getCount() {
            return timestamps.size();
        }
    }

    private static class TokenBucket {
        private final long capacity;
        private final long refillRate;
        private long tokens;
        private long lastRefill;

        public TokenBucket(long capacity, long refillRate) {
            this.capacity = capacity;
            this.refillRate = refillRate;
            this.tokens = capacity;
            this.lastRefill = System.currentTimeMillis();
        }

        public synchronized boolean tryConsume(long amount) {
            refill();

            if (tokens >= amount) {
                tokens -= amount;
                return true;
            }
            return false;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            long elapsed = now - lastRefill;
            long newTokens = (elapsed * refillRate) / 1000; // tokens per second

            if (newTokens > 0) {
                tokens = Math.min(capacity, tokens + newTokens);
                lastRefill = now;
            }
        }

        public long getCurrentRate() {
            return (capacity - tokens) * 1000 / windowSize.toMillis();
        }
    }

    private static class LeakyBucket {
        private final int capacity;
        private final Queue<Long> requests;

        public LeakyBucket(int capacity) {
            this.capacity = capacity;
            this.requests = new ConcurrentLinkedQueue<>();
        }

        public boolean tryAcquire() {
            long now = System.currentTimeMillis();
            cleanOldRequests(now);

            if (requests.size() < capacity) {
                requests.offer(now);
                return true;
            }
            return false;
        }

        private void cleanOldRequests(long now) {
            while (!requests.isEmpty() && 
                   now - requests.peek() > 1000) {
                requests.poll();
            }
        }

        public int getCurrentRate() {
            return requests.size();
        }
    }

    private static class AdaptiveRateLimiter {
        private volatile int currentLimit;
        private final double increaseFactor = 1.1;
        private final double decreaseFactor = 0.9;
        private final int minLimit = 10;
        private final int maxLimit = 1000;

        public AdaptiveRateLimiter() {
            this.currentLimit = 100; // Start with moderate limit
        }

        public boolean checkRate(PacketWrapper packet) {
            // Implementation depends on traffic patterns
            return true;
        }

        public void updateLimits(Queue<RateSnapshot> history) {
            if (history.isEmpty()) return;

            // Calculate average rates
            double avgRate = calculateAverageRate(history);
            
            // Adjust limits based on usage patterns
            if (avgRate < currentLimit * 0.8) {
                // Decrease limit if underutilized
                currentLimit = Math.max(minLimit, 
                    (int)(currentLimit * decreaseFactor));
            } else if (avgRate > currentLimit * 0.9) {
                // Increase limit if near capacity
                currentLimit = Math.min(maxLimit, 
                    (int)(currentLimit * increaseFactor));
            }
        }

        private double calculateAverageRate(Queue<RateSnapshot> history) {
            return history.stream()
                .mapToInt(s -> s.packetRate)
                .average()
                .orElse(0.0);
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("packet_rate", packetCounter.getCount());
        stats.put("bandwidth_rate", bandwidthLimiter.getCurrentRate());
        stats.put("request_rate", requestLimiter.getCurrentRate());
        stats.put("adaptive_limit", adaptiveLimiter.currentLimit);

        Map<String, Integer> packetCounts = new HashMap<>();
        packetStats.forEach((type, stats) -> 
            packetCounts.put(type.getSimpleName(), stats.count.get()));
        stats.put("packet_counts", packetCounts);

        return stats;
    }

    public Queue<RateSnapshot> getRateHistory() {
        return new LinkedList<>(rateHistory);
    }
}