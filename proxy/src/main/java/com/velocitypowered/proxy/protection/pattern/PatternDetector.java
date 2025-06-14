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
 * Current Date and Time (UTC): 2025-06-14 10:04:37
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.pattern;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class PatternDetector {
    private static final Logger logger = LogManager.getLogger(PatternDetector.class);

    // Pattern detection components
    private final SequenceDetector sequenceDetector;
    private final FrequencyAnalyzer frequencyAnalyzer;
    private final TimingAnalyzer timingAnalyzer;
    private final BehaviorMatcher behaviorMatcher;

    // Pattern tracking
    private final Map<InetAddress, PatternHistory> patternHistories;
    private final Cache<String, List<PatternMatch>> recentMatches;
    private final Map<String, AtomicInteger> patternStats;

    // Configuration
    private final int maxSequenceLength;
    private final int minFrequencyThreshold;
    private final Duration timingWindow;
    private final int maxPatternMatches;

    public PatternDetector() {
        // Initialize components
        this.sequenceDetector = new SequenceDetector();
        this.frequencyAnalyzer = new FrequencyAnalyzer();
        this.timingAnalyzer = new TimingAnalyzer();
        this.behaviorMatcher = new BehaviorMatcher();

        // Initialize collections
        this.patternHistories = new ConcurrentHashMap<>();
        this.recentMatches = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();
        this.patternStats = new ConcurrentHashMap<>();

        // Load configuration
        this.maxSequenceLength = 100;
        this.minFrequencyThreshold = 10;
        this.timingWindow = Duration.ofMinutes(5);
        this.maxPatternMatches = 1000;

        // Start maintenance tasks
        startMaintenanceTasks();
    }

    public boolean detectPattern(InetAddress address, String action) {
        try {
            // Get or create pattern history
            PatternHistory history = patternHistories.computeIfAbsent(address,
                k -> new PatternHistory());

            // Record action
            history.recordAction(action);

            // Perform pattern detection
            boolean hasPattern = false;

            // Check sequence patterns
            if (sequenceDetector.detectPattern(history)) {
                recordMatch("sequence", address, action);
                hasPattern = true;
            }

            // Check frequency patterns
            if (frequencyAnalyzer.analyzeFrequency(history)) {
                recordMatch("frequency", address, action);
                hasPattern = true;
            }

            // Check timing patterns
            if (timingAnalyzer.analyzeTiming(history)) {
                recordMatch("timing", address, action);
                hasPattern = true;
            }

            // Check behavior patterns
            if (behaviorMatcher.matchBehavior(history)) {
                recordMatch("behavior", address, action);
                hasPattern = true;
            }

            return hasPattern;

        } catch (Exception e) {
            logger.error("Error detecting patterns for " + address, e);
            return false;
        }
    }

    private void recordMatch(String type, InetAddress address, String action) {
        try {
            PatternMatch match = new PatternMatch(type, address, action);
            
            List<PatternMatch> matches = recentMatches.get(type,
                () -> new CopyOnWriteArrayList<>());
            matches.add(match);

            // Maintain maximum size
            while (matches.size() > maxPatternMatches) {
                matches.remove(0);
            }

            // Update statistics
            patternStats.computeIfAbsent(type, k -> new AtomicInteger())
                       .incrementAndGet();

        } catch (Exception e) {
            logger.error("Error recording pattern match", e);
        }
    }

    private void startMaintenanceTasks() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactoryBuilder()
                .setNameFormat("pattern-detector-%d")
                .setDaemon(true)
                .build()
        );

        // Clean up old histories
        executor.scheduleAtFixedRate(() -> {
            try {
                cleanupOldHistories();
            } catch (Exception e) {
                logger.error("Error cleaning up pattern histories", e);
            }
        }, 1, 1, TimeUnit.HOURS);
    }

    private void cleanupOldHistories() {
        long cutoff = System.currentTimeMillis() - Duration.ofHours(24).toMillis();
        patternHistories.entrySet().removeIf(entry -> 
            entry.getValue().getLastUpdate() < cutoff);
    }

    private static class SequenceDetector {
        public boolean detectPattern(PatternHistory history) {
            List<String> sequence = history.getRecentSequence();
            if (sequence.size() < 2) return false;

            // Check for repeating sequences
            return hasRepeatingSequence(sequence);
        }

        private boolean hasRepeatingSequence(List<String> sequence) {
            int length = sequence.size();
            for (int size = 2; size <= length/2; size++) {
                if (isRepeatingSequence(sequence, size)) {
                    return true;
                }
            }
            return false;
        }

        private boolean isRepeatingSequence(List<String> sequence, int size) {
            List<String> pattern = sequence.subList(0, size);
            for (int i = size; i + size <= sequence.size(); i += size) {
                List<String> current = sequence.subList(i, i + size);
                if (!pattern.equals(current)) {
                    return false;
                }
            }
            return true;
        }
    }

    private static class FrequencyAnalyzer {
        public boolean analyzeFrequency(PatternHistory history) {
            Map<String, Integer> frequencies = history.getActionFrequencies();
            
            // Check for high frequency actions
            return frequencies.values().stream()
                .anyMatch(count -> count >= 10);
        }
    }

    private static class TimingAnalyzer {
        public boolean analyzeTiming(PatternHistory history) {
            List<Long> timestamps = history.getTimestamps();
            if (timestamps.size() < 2) return false;

            // Check for suspicious timing patterns
            return hasTimingPattern(timestamps);
        }

        private boolean hasTimingPattern(List<Long> timestamps) {
            long[] intervals = new long[timestamps.size() - 1];
            for (int i = 1; i < timestamps.size(); i++) {
                intervals[i-1] = timestamps.get(i) - timestamps.get(i-1);
            }

            // Check for consistent intervals
            return hasConsistentIntervals(intervals);
        }

        private boolean hasConsistentIntervals(long[] intervals) {
            if (intervals.length < 3) return false;

            long sum = 0;
            long sumSquares = 0;
            for (long interval : intervals) {
                sum += interval;
                sumSquares += interval * interval;
            }

            double mean = sum / (double) intervals.length;
            double variance = (sumSquares / intervals.length) - (mean * mean);
            double stdDev = Math.sqrt(variance);

            // If standard deviation is low, intervals are consistent
            return stdDev < mean * 0.1;
        }
    }

    private static class BehaviorMatcher {
        public boolean matchBehavior(PatternHistory history) {
            List<String> actions = history.getRecentActions();
            if (actions.size() < 3) return false;

            // Check for known behavior patterns
            return matchesKnownPattern(actions);
        }

        private boolean matchesKnownPattern(List<String> actions) {
            // Implementation for matching known behavior patterns
            return false;
        }
    }

    private static class PatternHistory {
        private final Queue<String> recentActions;
        private final Queue<Long> timestamps;
        private final Map<String, Integer> actionFrequencies;
        private volatile long lastUpdate;

        public PatternHistory() {
            this.recentActions = new ConcurrentLinkedQueue<>();
            this.timestamps = new ConcurrentLinkedQueue<>();
            this.actionFrequencies = new ConcurrentHashMap<>();
            this.lastUpdate = System.currentTimeMillis();
        }

        public void recordAction(String action) {
            recentActions.offer(action);
            timestamps.offer(System.currentTimeMillis());
            actionFrequencies.merge(action, 1, Integer::sum);
            lastUpdate = System.currentTimeMillis();

            // Maintain size limits
            while (recentActions.size() > 100) {
                recentActions.poll();
                timestamps.poll();
            }
        }

        public List<String> getRecentSequence() {
            return new ArrayList<>(recentActions);
        }

        public List<String> getRecentActions() {
            return new ArrayList<>(recentActions);
        }

        public List<Long> getTimestamps() {
            return new ArrayList<>(timestamps);
        }

        public Map<String, Integer> getActionFrequencies() {
            return new HashMap<>(actionFrequencies);
        }

        public long getLastUpdate() {
            return lastUpdate;
        }
    }

    private static class PatternMatch {
        private final String type;
        private final InetAddress address;
        private final String action;
        private final long timestamp;

        public PatternMatch(String type, InetAddress address, String action) {
            this.type = type;
            this.address = address;
            this.action = action;
            this.timestamp = System.currentTimeMillis();
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        
        Map<String, Integer> matchCounts = new HashMap<>();
        patternStats.forEach((type, count) -> 
            matchCounts.put(type, count.get()));
        stats.put("pattern_matches", matchCounts);
        
        stats.put("active_histories", patternHistories.size());
        
        return stats;
    }

    public List<PatternMatch> getRecentMatches(String type) {
        return recentMatches.getIfPresent(type);
    }
}