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
 * Current Date and Time (UTC): 2025-06-14 08:45:51
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.behavior;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.netty.channel.ChannelHandlerContext;
import com.velocitypowered.proxy.protocol.packet.PacketWrapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class BehaviorAnalyzer {
    private static final Logger logger = LogManager.getLogger(BehaviorAnalyzer.class);

    // Analysis components
    private final PatternDetector patternDetector;
    private final AnomalyDetector anomalyDetector;
    private final SessionAnalyzer sessionAnalyzer;
    private final ProfileBuilder profileBuilder;

    // Data tracking
    private final Map<InetAddress, BehaviorProfile> profiles;
    private final Cache<InetAddress, SessionData> sessions;
    private final Map<InetAddress, Queue<BehaviorEvent>> eventHistory;

    // Configuration
    private final int patternThreshold;
    private final double anomalyThreshold;
    private final Duration sessionTimeout;
    private final int maxEventsPerSession;

    public BehaviorAnalyzer() {
        // Initialize analyzers
        this.patternDetector = new PatternDetector();
        this.anomalyDetector = new AnomalyDetector();
        this.sessionAnalyzer = new SessionAnalyzer();
        this.profileBuilder = new ProfileBuilder();

        // Initialize collections
        this.profiles = new ConcurrentHashMap<>();
        this.sessions = CacheBuilder.newBuilder()
            .expireAfterWrite(30, TimeUnit.MINUTES)
            .build();
        this.eventHistory = new ConcurrentHashMap<>();

        // Load configuration
        this.patternThreshold = 50;
        this.anomalyThreshold = 0.8;
        this.sessionTimeout = Duration.ofMinutes(30);
        this.maxEventsPerSession = 1000;
    }

    public boolean analyzeBehavior(InetAddress address, ConnectionState state, PacketWrapper packet) {
        try {
            // Get or create behavior profile
            BehaviorProfile profile = profiles.computeIfAbsent(address,
                k -> profileBuilder.createProfile());

            // Get or create session
            SessionData session = getOrCreateSession(address);

            // Record event
            BehaviorEvent event = new BehaviorEvent(packet, state);
            recordEvent(address, event);

            // Pattern analysis
            if (patternDetector.detectSuspiciousPattern(profile, event)) {
                logger.warn("Suspicious pattern detected from {}", address);
                return false;
            }

            // Anomaly detection
            if (anomalyDetector.detectAnomaly(profile, event)) {
                logger.warn("Behavioral anomaly detected from {}", address);
                return false;
            }

            // Session analysis
            if (!sessionAnalyzer.analyzeSession(session, event)) {
                logger.warn("Session anomaly detected from {}", address);
                return false;
            }

            // Update profile
            profile.updateWithEvent(event);

            return true;

        } catch (Exception e) {
            logger.error("Error analyzing behavior for " + address, e);
            return false;
        }
    }

    private SessionData getOrCreateSession(InetAddress address) {
        SessionData session = sessions.getIfPresent(address);
        if (session == null) {
            session = new SessionData();
            sessions.put(address, session);
        }
        return session;
    }

    private void recordEvent(InetAddress address, BehaviorEvent event) {
        Queue<BehaviorEvent> events = eventHistory.computeIfAbsent(address,
            k -> new ConcurrentLinkedQueue<>());
        
        events.offer(event);

        // Limit history size
        while (events.size() > maxEventsPerSession) {
            events.poll();
        }
    }

    private static class BehaviorProfile {
        private final Map<String, AtomicInteger> actionCounts;
        private final Queue<Long> actionTimestamps;
        private final Set<String> uniquePatterns;
        private volatile long lastUpdate;

        public BehaviorProfile() {
            this.actionCounts = new ConcurrentHashMap<>();
            this.actionTimestamps = new ConcurrentLinkedQueue<>();
            this.uniquePatterns = Collections.newSetFromMap(new ConcurrentHashMap<>());
            this.lastUpdate = System.currentTimeMillis();
        }

        public void updateWithEvent(BehaviorEvent event) {
            String action = event.getAction();
            actionCounts.computeIfAbsent(action, k -> new AtomicInteger()).incrementAndGet();
            actionTimestamps.offer(System.currentTimeMillis());
            uniquePatterns.add(event.getPattern());
            lastUpdate = System.currentTimeMillis();

            // Clean old timestamps
            cleanOldTimestamps();
        }

        private void cleanOldTimestamps() {
            long cutoff = System.currentTimeMillis() - Duration.ofMinutes(5).toMillis();
            while (!actionTimestamps.isEmpty() && actionTimestamps.peek() < cutoff) {
                actionTimestamps.poll();
            }
        }
    }

    private static class SessionData {
        private final Map<String, Integer> actionSequence;
        private final Set<String> uniqueActions;
        private final long startTime;
        private volatile long lastActivity;
        private final AtomicInteger eventCount;

        public SessionData() {
            this.actionSequence = new ConcurrentHashMap<>();
            this.uniqueActions = Collections.newSetFromMap(new ConcurrentHashMap<>());
            this.startTime = System.currentTimeMillis();
            this.lastActivity = startTime;
            this.eventCount = new AtomicInteger();
        }

        public void recordAction(String action) {
            actionSequence.merge(action, 1, Integer::sum);
            uniqueActions.add(action);
            lastActivity = System.currentTimeMillis();
            eventCount.incrementAndGet();
        }
    }

    private static class BehaviorEvent {
        private final PacketWrapper packet;
        private final ConnectionState state;
        private final long timestamp;

        public BehaviorEvent(PacketWrapper packet, ConnectionState state) {
            this.packet = packet;
            this.state = state;
            this.timestamp = System.currentTimeMillis();
        }

        public String getAction() {
            return packet.getClass().getSimpleName();
        }

        public String getPattern() {
            return state.getClass().getSimpleName() + ":" + getAction();
        }
    }

    private class PatternDetector {
        public boolean detectSuspiciousPattern(BehaviorProfile profile, BehaviorEvent event) {
            // Check action frequency
            AtomicInteger count = profile.actionCounts.get(event.getAction());
            if (count != null && count.get() > patternThreshold) {
                return true;
            }

            // Check pattern uniqueness
            if (profile.uniquePatterns.size() > patternThreshold) {
                return true;
            }

            return false;
        }
    }

    private class AnomalyDetector {
        public boolean detectAnomaly(BehaviorProfile profile, BehaviorEvent event) {
            // Check action rate
            if (isAnomalousRate(profile.actionTimestamps)) {
                return true;
            }

            // Check pattern distribution
            if (isAnomalousDistribution(profile.actionCounts)) {
                return true;
            }

            return false;
        }

        private boolean isAnomalousRate(Queue<Long> timestamps) {
            if (timestamps.size() < 2) {
                return false;
            }

            long[] times = timestamps.stream().mapToLong(Long::valueOf).toArray();
            double mean = calculateMean(times);
            double stdDev = calculateStdDev(times, mean);

            return stdDev > anomalyThreshold;
        }

        private boolean isAnomalousDistribution(Map<String, AtomicInteger> counts) {
            // Implementation for distribution analysis
            return false;
        }

        private double calculateMean(long[] values) {
            return Arrays.stream(values).average().orElse(0.0);
        }

        private double calculateStdDev(long[] values, double mean) {
            return Math.sqrt(Arrays.stream(values)
                .mapToDouble(v -> Math.pow(v - mean, 2))
                .average()
                .orElse(0.0));
        }
    }

    private class SessionAnalyzer {
        public boolean analyzeSession(SessionData session, BehaviorEvent event) {
            // Record action
            session.recordAction(event.getAction());

            // Check session duration
            if (System.currentTimeMillis() - session.startTime > sessionTimeout.toMillis()) {
                return false;
            }

            // Check event count
            if (session.eventCount.get() > maxEventsPerSession) {
                return false;
            }

            // Check action variety
            if (isAnomalousVariety(session)) {
                return false;
            }

            return true;
        }

        private boolean isAnomalousVariety(SessionData session) {
            // Check if the ratio of unique actions to total actions is too low
            double uniqueRatio = (double) session.uniqueActions.size() / session.eventCount.get();
            return uniqueRatio < 0.1; // If less than 10% unique actions
        }
    }

    private class ProfileBuilder {
        public BehaviorProfile createProfile() {
            return new BehaviorProfile();
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats(InetAddress address) {
        Map<String, Object> stats = new HashMap<>();
        
        BehaviorProfile profile = profiles.get(address);
        if (profile != null) {
            stats.put("action_counts", profile.actionCounts);
            stats.put("unique_patterns", profile.uniquePatterns.size());
            stats.put("last_update", profile.lastUpdate);
        }

        SessionData session = sessions.getIfPresent(address);
        if (session != null) {
            stats.put("session_duration", System.currentTimeMillis() - session.startTime);
            stats.put("event_count", session.eventCount.get());
            stats.put("unique_actions", session.uniqueActions.size());
        }

        return stats;
    }
}