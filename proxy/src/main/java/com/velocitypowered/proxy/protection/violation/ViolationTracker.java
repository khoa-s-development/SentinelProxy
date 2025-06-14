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
 * Current Date and Time (UTC): 2025-06-14 08:59:19
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.violation;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.netty.channel.ChannelHandlerContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ViolationTracker {
    private static final Logger logger = LogManager.getLogger(ViolationTracker.class);

    // Violation tracking components
    private final ViolationCounter violationCounter;
    private final PenaltyManager penaltyManager;
    private final NotificationSystem notificationSystem;
    private final AuditLogger auditLogger;

    // Data tracking
    private final Map<InetAddress, ViolationHistory> violationHistories;
    private final Cache<InetAddress, List<Violation>> recentViolations;
    private final Map<String, AtomicInteger> violationTypeStats;

    // Configuration
    private final int maxViolationsPerHour;
    private final int maxViolationsTotal;
    private final Duration violationExpiry;
    private final int notificationThreshold;

    public ViolationTracker() {
        // Initialize components
        this.violationCounter = new ViolationCounter();
        this.penaltyManager = new PenaltyManager();
        this.notificationSystem = new NotificationSystem();
        this.auditLogger = new AuditLogger();

        // Initialize collections
        this.violationHistories = new ConcurrentHashMap<>();
        this.recentViolations = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();
        this.violationTypeStats = new ConcurrentHashMap<>();

        // Load configuration
        this.maxViolationsPerHour = 10;
        this.maxViolationsTotal = 50;
        this.violationExpiry = Duration.ofHours(24);
        this.notificationThreshold = 5;

        // Start maintenance tasks
        startMaintenanceTasks();
    }

    public void recordViolation(ChannelHandlerContext ctx, String type, String reason) {
        InetSocketAddress socketAddress = (InetSocketAddress) ctx.channel().remoteAddress();
        InetAddress address = socketAddress.getAddress();

        try {
            // Create violation record
            Violation violation = new Violation(type, reason);

            // Update violation history
            ViolationHistory history = violationHistories.computeIfAbsent(address,
                k -> new ViolationHistory());
            history.addViolation(violation);

            // Update recent violations
            updateRecentViolations(address, violation);

            // Update violation stats
            updateViolationStats(type);

            // Check violation thresholds
            if (hasExceededThresholds(address)) {
                handleExcessiveViolations(ctx, address);
                return;
            }

            // Apply penalty if needed
            if (shouldApplyPenalty(history)) {
                penaltyManager.applyPenalty(ctx, address, history);
            }

            // Send notification if needed
            if (shouldNotify(history)) {
                notificationSystem.sendNotification(address, history);
            }

            // Log violation
            auditLogger.logViolation(address, violation);

        } catch (Exception e) {
            logger.error("Error recording violation for " + address, e);
        }
    }

    private void updateRecentViolations(InetAddress address, Violation violation) {
        try {
            List<Violation> violations = recentViolations.get(address,
                () -> new CopyOnWriteArrayList<>());
            violations.add(violation);
        } catch (ExecutionException e) {
            logger.error("Error updating recent violations", e);
        }
    }

    private void updateViolationStats(String type) {
        violationTypeStats.computeIfAbsent(type, k -> new AtomicInteger())
                         .incrementAndGet();
    }

    private boolean hasExceededThresholds(InetAddress address) {
        ViolationHistory history = violationHistories.get(address);
        if (history == null) return false;

        return history.getRecentViolationCount() > maxViolationsPerHour ||
               history.getTotalViolationCount() > maxViolationsTotal;
    }

    private boolean shouldApplyPenalty(ViolationHistory history) {
        return history.getRecentViolationCount() >= 3;
    }

    private boolean shouldNotify(ViolationHistory history) {
        return history.getTotalViolationCount() >= notificationThreshold;
    }

    private void handleExcessiveViolations(ChannelHandlerContext ctx, InetAddress address) {
        logger.warn("Excessive violations from {}, disconnecting", address);
        ctx.close();
        penaltyManager.banAddress(address, Duration.ofHours(1));
        notificationSystem.sendAlert(address, "Excessive violations detected");
    }

    private void startMaintenanceTasks() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactoryBuilder()
                .setNameFormat("violation-tracker-%d")
                .setDaemon(true)
                .build()
        );

        // Clean up old violations
        executor.scheduleAtFixedRate(() -> {
            try {
                cleanupOldViolations();
            } catch (Exception e) {
                logger.error("Error cleaning up violations", e);
            }
        }, 1, 1, TimeUnit.HOURS);
    }

    private void cleanupOldViolations() {
        long cutoff = System.currentTimeMillis() - violationExpiry.toMillis();
        violationHistories.values().forEach(history -> 
            history.removeOldViolations(cutoff));
    }

    private static class ViolationHistory {
        private final Queue<Violation> violations;
        private final AtomicInteger totalViolations;
        private final AtomicInteger recentViolations;

        public ViolationHistory() {
            this.violations = new ConcurrentLinkedQueue<>();
            this.totalViolations = new AtomicInteger();
            this.recentViolations = new AtomicInteger();
        }

        public void addViolation(Violation violation) {
            violations.offer(violation);
            totalViolations.incrementAndGet();
            recentViolations.incrementAndGet();
        }

        public void removeOldViolations(long cutoff) {
            while (!violations.isEmpty() && 
                   violations.peek().timestamp < cutoff) {
                violations.poll();
                recentViolations.decrementAndGet();
            }
        }

        public int getTotalViolationCount() {
            return totalViolations.get();
        }

        public int getRecentViolationCount() {
            return recentViolations.get();
        }
    }

    private static class Violation {
        private final String type;
        private final String reason;
        private final long timestamp;

        public Violation(String type, String reason) {
            this.type = type;
            this.reason = reason;
            this.timestamp = System.currentTimeMillis();
        }
    }

    private static class ViolationCounter {
        private final Map<InetAddress, AtomicInteger> hourlyCounters;

        public ViolationCounter() {
            this.hourlyCounters = new ConcurrentHashMap<>();
        }

        public void incrementCounter(InetAddress address) {
            hourlyCounters.computeIfAbsent(address, k -> new AtomicInteger())
                         .incrementAndGet();
        }
    }

    private static class PenaltyManager {
        private final Map<InetAddress, Long> bannedAddresses;

        public PenaltyManager() {
            this.bannedAddresses = new ConcurrentHashMap<>();
        }

        public void applyPenalty(ChannelHandlerContext ctx, 
                                InetAddress address,
                                ViolationHistory history) {
            if (history.getRecentViolationCount() >= 5) {
                ctx.channel().close();
            }
        }

        public void banAddress(InetAddress address, Duration duration) {
            bannedAddresses.put(address, 
                System.currentTimeMillis() + duration.toMillis());
        }
    }

    private static class NotificationSystem {
        public void sendNotification(InetAddress address, ViolationHistory history) {
            // Implementation for sending notifications
        }

        public void sendAlert(InetAddress address, String message) {
            // Implementation for sending alerts
        }
    }

    private static class AuditLogger {
        public void logViolation(InetAddress address, Violation violation) {
            logger.info("Violation from {}: {} - {}", 
                address, violation.type, violation.reason);
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        
        Map<String, Integer> typeStats = new HashMap<>();
        violationTypeStats.forEach((type, count) -> 
            typeStats.put(type, count.get()));
        stats.put("violation_types", typeStats);
        
        stats.put("total_violations", violationHistories.values().stream()
            .mapToInt(ViolationHistory::getTotalViolationCount)
            .sum());
            
        return stats;
    }

    public List<Violation> getRecentViolations(InetAddress address) {
        return recentViolations.getIfPresent(address);
    }
}