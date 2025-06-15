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
 * Current Date and Time (UTC): 2025-06-14 08:54:39
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.threshold;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.function.ToDoubleFunction;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class DynamicThresholds {
    private static final Logger logger = LogManager.getLogger(DynamicThresholds.class);

    // Threshold components
    private final ConnectionThreshold connectionThreshold;
    private final PacketThreshold packetThreshold;
    private final BandwidthThreshold bandwidthThreshold;
    private final BehaviorThreshold behaviorThreshold;

    // Data tracking
    private final Map<String, ThresholdStats> thresholdStats;
    private final Queue<ThresholdSnapshot> thresholdHistory;
    private final Cache<String, AtomicInteger> violationCounts;

    // Configuration
    private final double baseMultiplier;
    private final double minThresholdRatio;
    private final double maxThresholdRatio;
    private final Duration adjustmentInterval;
    private final int historySize;

    public DynamicThresholds() {
        // Initialize thresholds
        this.connectionThreshold = new ConnectionThreshold();
        this.packetThreshold = new PacketThreshold();
        this.bandwidthThreshold = new BandwidthThreshold();
        this.behaviorThreshold = new BehaviorThreshold();

        // Initialize collections
        this.thresholdStats = new ConcurrentHashMap<>();
        this.thresholdHistory = new ConcurrentLinkedQueue<>();
        this.violationCounts = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();

        // Load configuration
        this.baseMultiplier = 1.5;
        this.minThresholdRatio = 0.5;
        this.maxThresholdRatio = 3.0;
        this.adjustmentInterval = Duration.ofMinutes(5);
        this.historySize = 12; // 1 hour of 5-minute snapshots

        // Start maintenance tasks
        startMaintenanceTasks();
    }

    public void updateMetrics(Map<String, Object> metrics) {
        try {
            long now = System.currentTimeMillis();

            // Update threshold stats
            ThresholdStats stats = new ThresholdStats(metrics);
            thresholdStats.put(stats.getKey(), stats);

            // Update thresholds
            connectionThreshold.update(stats);
            packetThreshold.update(stats);
            bandwidthThreshold.update(stats);
            behaviorThreshold.update(stats);

            // Record snapshot
            recordSnapshot(now);

            // Clean old data
            cleanOldData(now);

        } catch (Exception e) {
            logger.error("Error updating metrics", e);
        }
    }

    private void recordSnapshot(long timestamp) {
        ThresholdSnapshot snapshot = new ThresholdSnapshot(
            timestamp,
            connectionThreshold.getCurrentThreshold(),
            packetThreshold.getCurrentThreshold(),
            bandwidthThreshold.getCurrentThreshold(),
            behaviorThreshold.getCurrentThreshold()
        );

        thresholdHistory.offer(snapshot);

        // Maintain history size
        while (thresholdHistory.size() > historySize) {
            thresholdHistory.poll();
        }
    }

    private void cleanOldData(long now) {
        // Clean old stats
        thresholdStats.entrySet().removeIf(entry ->
            now - entry.getValue().getTimestamp() > adjustmentInterval.toMillis());
    }

    private void startMaintenanceTasks() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactoryBuilder()
                .setNameFormat("dynamic-thresholds-%d")
                .setDaemon(true)
                .build()
        );

        // Adjust thresholds periodically
        executor.scheduleAtFixedRate(() -> {
            try {
                adjustThresholds();
            } catch (Exception e) {
                logger.error("Error adjusting thresholds", e);
            }
        }, 5, 5, TimeUnit.MINUTES);
    }

    private void adjustThresholds() {
        // Analyze recent history
        List<ThresholdSnapshot> snapshots = new ArrayList<>(thresholdHistory);
        if (snapshots.isEmpty()) return;

        // Calculate trends
        double connectionTrend = calculateTrend(snapshots, s -> s.connectionThreshold);
        double packetTrend = calculateTrend(snapshots, s -> s.packetThreshold);
        double bandwidthTrend = calculateTrend(snapshots, s -> s.bandwidthThreshold);
        double behaviorTrend = calculateTrend(snapshots, s -> s.behaviorThreshold);

        // Adjust thresholds based on trends
        connectionThreshold.adjustThreshold(connectionTrend);
        packetThreshold.adjustThreshold(packetTrend);
        bandwidthThreshold.adjustThreshold(bandwidthTrend);
        behaviorThreshold.adjustThreshold(behaviorTrend);
    }

    private double calculateTrend(List<ThresholdSnapshot> snapshots, 
                                ToDoubleFunction<ThresholdSnapshot> valueExtractor) {
        if (snapshots.size() < 2) return 0.0;

        double first = valueExtractor.applyAsDouble(snapshots.get(0));
        double last = valueExtractor.applyAsDouble(snapshots.get(snapshots.size() - 1));
        return (last - first) / first;
    }

    private abstract class BaseThreshold {
        protected volatile double currentThreshold;
        protected final double initialThreshold;
        protected final AtomicLong lastAdjustment;

        public BaseThreshold(double initialThreshold) {
            this.currentThreshold = initialThreshold;
            this.initialThreshold = initialThreshold;
            this.lastAdjustment = new AtomicLong(System.currentTimeMillis());
        }

        public abstract void update(ThresholdStats stats);

        public void adjustThreshold(double trend) {
            if (Math.abs(trend) < 0.1) return; // Ignore small changes

            double adjustmentFactor = 1.0 + (trend > 0 ? 0.1 : -0.1);
            double newThreshold = currentThreshold * adjustmentFactor;

            // Apply bounds
            newThreshold = Math.max(initialThreshold * minThresholdRatio,
                Math.min(initialThreshold * maxThresholdRatio, newThreshold));

            currentThreshold = newThreshold;
            lastAdjustment.set(System.currentTimeMillis());
        }

        public double getCurrentThreshold() {
            return currentThreshold;
        }
    }

    private class ConnectionThreshold extends BaseThreshold {
        public ConnectionThreshold() {
            super(100.0); // 100 connections per second
        }

        @Override
        public void update(ThresholdStats stats) {
            double connectionRate = stats.getMetric("connection_rate", 0.0);
            if (connectionRate > currentThreshold) {
                recordViolation("connection", stats.getKey());
            }
        }
    }

    private class PacketThreshold extends BaseThreshold {
        public PacketThreshold() {
            super(1000.0); // 1000 packets per second
        }

        @Override
        public void update(ThresholdStats stats) {
            double packetRate = stats.getMetric("packet_rate", 0.0);
            if (packetRate > currentThreshold) {
                recordViolation("packet", stats.getKey());
            }
        }
    }

    private class BandwidthThreshold extends BaseThreshold {
        public BandwidthThreshold() {
            super(1024 * 1024.0); // 1MB per second
        }

        @Override
        public void update(ThresholdStats stats) {
            double bandwidthRate = stats.getMetric("bandwidth_rate", 0.0);
            if (bandwidthRate > currentThreshold) {
                recordViolation("bandwidth", stats.getKey());
            }
        }
    }

    private class BehaviorThreshold extends BaseThreshold {
        public BehaviorThreshold() {
            super(10.0); // 10 anomalies per minute
        }

        @Override
        public void update(ThresholdStats stats) {
            double anomalyRate = stats.getMetric("anomaly_rate", 0.0);
            if (anomalyRate > currentThreshold) {
                recordViolation("behavior", stats.getKey());
            }
        }
    }

    private static class ThresholdStats {
        private final String key;
        private final Map<String, Double> metrics;
        private final long timestamp;

        public ThresholdStats(Map<String, Object> metrics) {
            this.key = UUID.randomUUID().toString();
            this.metrics = new HashMap<>();
            metrics.forEach((k, v) -> this.metrics.put(k, parseDouble(v)));
            this.timestamp = System.currentTimeMillis();
        }

        private double parseDouble(Object value) {
            if (value instanceof Number) {
                return ((Number) value).doubleValue();
            }
            try {
                return Double.parseDouble(value.toString());
            } catch (Exception e) {
                return 0.0;
            }
        }

        public String getKey() {
            return key;
        }

        public double getMetric(String name, double defaultValue) {
            return metrics.getOrDefault(name, defaultValue);
        }

        public long getTimestamp() {
            return timestamp;
        }
    }

    private static class ThresholdSnapshot {
        private final long timestamp;
        private final double connectionThreshold;
        private final double packetThreshold;
        private final double bandwidthThreshold;
        private final double behaviorThreshold;

        public ThresholdSnapshot(long timestamp, double connectionThreshold,
                               double packetThreshold, double bandwidthThreshold,
                               double behaviorThreshold) {
            this.timestamp = timestamp;
            this.connectionThreshold = connectionThreshold;
            this.packetThreshold = packetThreshold;
            this.bandwidthThreshold = bandwidthThreshold;
            this.behaviorThreshold = behaviorThreshold;
        }
    }

    private void recordViolation(String type, String key) {
        String violationKey = type + ":" + key;
        try {
            AtomicInteger count = violationCounts.get(violationKey,
                () -> new AtomicInteger());
            count.incrementAndGet();
        } catch (ExecutionException e) {
            logger.error("Error recording violation", e);
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("connection_threshold", connectionThreshold.getCurrentThreshold());
        stats.put("packet_threshold", packetThreshold.getCurrentThreshold());
        stats.put("bandwidth_threshold", bandwidthThreshold.getCurrentThreshold());
        stats.put("behavior_threshold", behaviorThreshold.getCurrentThreshold());

        Map<String, Integer> violations = new HashMap<>();
        violationCounts.asMap().forEach((key, count) ->
            violations.put(key, count.get()));
        stats.put("violations", violations);

        return stats;
    }

    public Queue<ThresholdSnapshot> getThresholdHistory() {
        return new LinkedList<>(thresholdHistory);
    }
}