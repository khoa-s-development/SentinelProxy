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
 * Current Date and Time (UTC): 2025-06-14 10:16:46
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.anomaly;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class AnomalyDetector {
    private static final Logger logger = LogManager.getLogger(AnomalyDetector.class);

    // Anomaly detection components
    private final StatisticalDetector statisticalDetector;
    private final BehavioralDetector behavioralDetector;
    private final TimeSeriesAnalyzer timeSeriesAnalyzer;
    private final OutlierDetector outlierDetector;

    // Data tracking
    private final Map<InetAddress, AnomalyProfile> anomalyProfiles;
    private final Cache<String, List<AnomalyEvent>> recentAnomalies;
    private final Map<String, AtomicInteger> anomalyStats;

    // Configuration
    private final double statisticalThreshold;
    private final double behavioralThreshold;
    private final Duration analysisWindow;
    private final int maxAnomalyEvents;

    public AnomalyDetector() {
        // Initialize components
        this.statisticalDetector = new StatisticalDetector();
        this.behavioralDetector = new BehavioralDetector();
        this.timeSeriesAnalyzer = new TimeSeriesAnalyzer();
        this.outlierDetector = new OutlierDetector();

        // Initialize collections
        this.anomalyProfiles = new ConcurrentHashMap<>();
        this.recentAnomalies = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();
        this.anomalyStats = new ConcurrentHashMap<>();

        // Load configuration
        this.statisticalThreshold = 2.0; // Standard deviations
        this.behavioralThreshold = 0.8; // Similarity score
        this.analysisWindow = Duration.ofMinutes(5);
        this.maxAnomalyEvents = 1000;

        // Start maintenance tasks
        startMaintenanceTasks();
    }

    public boolean detectAnomaly(InetAddress address, String action, Map<String, Object> metrics) {
        try {
            // Get or create anomaly profile
            AnomalyProfile profile = anomalyProfiles.computeIfAbsent(address,
                k -> new AnomalyProfile());

            // Record action and metrics
            profile.recordActivity(action, metrics);

            // Perform anomaly detection
            boolean isAnomaly = false;

            // Statistical analysis
            if (statisticalDetector.detectAnomaly(profile)) {
                recordAnomaly("statistical", address, action);
                isAnomaly = true;
            }

            // Behavioral analysis
            if (behavioralDetector.detectAnomaly(profile)) {
                recordAnomaly("behavioral", address, action);
                isAnomaly = true;
            }

            // Time series analysis
            if (timeSeriesAnalyzer.detectAnomaly(profile)) {
                recordAnomaly("timeseries", address, action);
                isAnomaly = true;
            }

            // Outlier detection
            if (outlierDetector.detectAnomaly(profile)) {
                recordAnomaly("outlier", address, action);
                isAnomaly = true;
            }

            return isAnomaly;

        } catch (Exception e) {
            logger.error("Error detecting anomalies for " + address, e);
            return false;
        }
    }

    private void recordAnomaly(String type, InetAddress address, String action) {
        try {
            AnomalyEvent event = new AnomalyEvent(type, address, action);
            
            List<AnomalyEvent> events = recentAnomalies.get(type,
                () -> new CopyOnWriteArrayList<>());
            events.add(event);

            // Maintain maximum size
            while (events.size() > maxAnomalyEvents) {
                events.remove(0);
            }

            // Update statistics
            anomalyStats.computeIfAbsent(type, k -> new AtomicInteger())
                       .incrementAndGet();

        } catch (Exception e) {
            logger.error("Error recording anomaly", e);
        }
    }

    private void startMaintenanceTasks() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactoryBuilder()
                .setNameFormat("anomaly-detector-%d")
                .setDaemon(true)
                .build()
        );

        // Clean up old profiles
        executor.scheduleAtFixedRate(() -> {
            try {
                cleanupOldProfiles();
            } catch (Exception e) {
                logger.error("Error cleaning up anomaly profiles", e);
            }
        }, 1, 1, TimeUnit.HOURS);
    }

    private void cleanupOldProfiles() {
        long cutoff = System.currentTimeMillis() - Duration.ofHours(24).toMillis();
        anomalyProfiles.entrySet().removeIf(entry -> 
            entry.getValue().getLastUpdate() < cutoff);
    }

    private static class StatisticalDetector {
        public boolean detectAnomaly(AnomalyProfile profile) {
            List<Double> values = profile.getMetricValues("rate");
            if (values.size() < 10) return false;

            // Calculate mean and standard deviation
            double mean = calculateMean(values);
            double stdDev = calculateStdDev(values, mean);

            // Check latest value
            double latest = values.get(values.size() - 1);
            return Math.abs(latest - mean) > 2 * stdDev;
        }

        private double calculateMean(List<Double> values) {
            return values.stream()
                .mapToDouble(Double::doubleValue)
                .average()
                .orElse(0.0);
        }

        private double calculateStdDev(List<Double> values, double mean) {
            return Math.sqrt(values.stream()
                .mapToDouble(v -> Math.pow(v - mean, 2))
                .average()
                .orElse(0.0));
        }
    }

    private static class BehavioralDetector {
        public boolean detectAnomaly(AnomalyProfile profile) {
            List<String> sequence = profile.getActionSequence();
            if (sequence.size() < 3) return false;

            // Check for abnormal behavior patterns
            return hasAbnormalPattern(sequence);
        }

        private boolean hasAbnormalPattern(List<String> sequence) {
            // Implementation for detecting abnormal behavior patterns
            return false;
        }
    }

    private static class TimeSeriesAnalyzer {
        public boolean detectAnomaly(AnomalyProfile profile) {
            List<TimeSeriesPoint> points = profile.getTimeSeriesData();
            if (points.size() < 10) return false;

            // Perform time series analysis
            return detectTimeSeriesAnomaly(points);
        }

        private boolean detectTimeSeriesAnomaly(List<TimeSeriesPoint> points) {
            // Implementation for time series anomaly detection
            return false;
        }
    }

    private static class OutlierDetector {
        public boolean detectAnomaly(AnomalyProfile profile) {
            Map<String, Double> metrics = profile.getCurrentMetrics();
            if (metrics.isEmpty()) return false;

            // Check for metric outliers
            return hasMetricOutliers(metrics);
        }

        private boolean hasMetricOutliers(Map<String, Double> metrics) {
            // Implementation for outlier detection
            return false;
        }
    }

    private static class AnomalyProfile {
        private final List<String> actionSequence;
        private final List<TimeSeriesPoint> timeSeriesData;
        private final Map<String, List<Double>> metricHistory;
        private final Map<String, Double> currentMetrics;
        private volatile long lastUpdate;

        public AnomalyProfile() {
            this.actionSequence = new CopyOnWriteArrayList<>();
            this.timeSeriesData = new CopyOnWriteArrayList<>();
            this.metricHistory = new ConcurrentHashMap<>();
            this.currentMetrics = new ConcurrentHashMap<>();
            this.lastUpdate = System.currentTimeMillis();
        }

        public void recordActivity(String action, Map<String, Object> metrics) {
            // Record action
            actionSequence.add(action);
            if (actionSequence.size() > 100) {
                actionSequence.remove(0);
            }

            // Record time series point
            TimeSeriesPoint point = new TimeSeriesPoint(
                System.currentTimeMillis(),
                metrics
            );
            timeSeriesData.add(point);
            if (timeSeriesData.size() > 1000) {
                timeSeriesData.remove(0);
            }

            // Update metrics
            metrics.forEach((key, value) -> {
                double doubleValue = parseDouble(value);
                List<Double> history = metricHistory.computeIfAbsent(key,
                    k -> new ArrayList<>());
                history.add(doubleValue);
                currentMetrics.put(key, doubleValue);
            });

            lastUpdate = System.currentTimeMillis();
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

        public List<String> getActionSequence() {
            return new ArrayList<>(actionSequence);
        }

        public List<TimeSeriesPoint> getTimeSeriesData() {
            return new ArrayList<>(timeSeriesData);
        }

        public List<Double> getMetricValues(String metric) {
            return metricHistory.getOrDefault(metric, Collections.emptyList());
        }

        public Map<String, Double> getCurrentMetrics() {
            return new HashMap<>(currentMetrics);
        }

        public long getLastUpdate() {
            return lastUpdate;
        }
    }

    private static class TimeSeriesPoint {
        private final long timestamp;
        private final Map<String, Object> metrics;

        public TimeSeriesPoint(long timestamp, Map<String, Object> metrics) {
            this.timestamp = timestamp;
            this.metrics = new HashMap<>(metrics);
        }
    }

    private static class AnomalyEvent {
        private final String type;
        private final InetAddress address;
        private final String action;
        private final long timestamp;

        public AnomalyEvent(String type, InetAddress address, String action) {
            this.type = type;
            this.address = address;
            this.action = action;
            this.timestamp = System.currentTimeMillis();
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        
        Map<String, Integer> anomalyCounts = new HashMap<>();
        anomalyStats.forEach((type, count) -> 
            anomalyCounts.put(type, count.get()));
        stats.put("anomaly_counts", anomalyCounts);
        
        stats.put("active_profiles", anomalyProfiles.size());
        
        return stats;
    }

    public List<AnomalyEvent> getRecentAnomalies(String type) {
        return recentAnomalies.getIfPresent(type);
    }
}