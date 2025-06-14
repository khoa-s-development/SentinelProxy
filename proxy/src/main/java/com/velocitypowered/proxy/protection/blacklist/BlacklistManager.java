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
 * Current Date and Time (UTC): 2025-06-14 09:01:32
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.blacklist;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public class BlacklistManager {
    private static final Logger logger = LogManager.getLogger(BlacklistManager.class);

    // Blacklist collections
    private final Set<InetAddress> permanentBlacklist;
    private final Cache<InetAddress, Long> temporaryBlacklist;
    private final Set<String> bannedPatterns;
    private final Map<InetAddress, BlacklistEntry> blacklistEntries;

    // Statistics tracking
    private final Map<String, AtomicInteger> blockStats;
    private final Queue<BlacklistEvent> recentEvents;

    // Configuration
    private final int maxPatternLength;
    private final Duration defaultBanDuration;
    private final int maxRecentEvents;
    private final int maxEntriesPerIP;

    public BlacklistManager() {
        // Initialize collections
        this.permanentBlacklist = ConcurrentHashMap.newKeySet();
        this.temporaryBlacklist = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build();
        this.bannedPatterns = ConcurrentHashMap.newKeySet();
        this.blacklistEntries = new ConcurrentHashMap<>();
        
        // Initialize statistics
        this.blockStats = new ConcurrentHashMap<>();
        this.recentEvents = new ConcurrentLinkedQueue<>();

        // Load configuration
        this.maxPatternLength = 256;
        this.defaultBanDuration = Duration.ofHours(24);
        this.maxRecentEvents = 1000;
        this.maxEntriesPerIP = 5;

        // Start maintenance tasks
        startMaintenanceTasks();
    }

    public void blacklistPermanently(InetAddress address, String reason) {
        try {
            permanentBlacklist.add(address);
            BlacklistEntry entry = new BlacklistEntry(address, reason, -1);
            blacklistEntries.put(address, entry);
            
            logEvent("PERMANENT", address, reason);
            logger.info("Permanently blacklisted {}: {}", address, reason);
        } catch (Exception e) {
            logger.error("Error adding permanent blacklist entry for " + address, e);
        }
    }

    public void blacklistTemporarily(InetAddress address, Duration duration, String reason) {
        try {
            long expiryTime = System.currentTimeMillis() + duration.toMillis();
            temporaryBlacklist.put(address, expiryTime);
            BlacklistEntry entry = new BlacklistEntry(address, reason, expiryTime);
            blacklistEntries.put(address, entry);
            
            logEvent("TEMPORARY", address, reason);
            logger.info("Temporarily blacklisted {} for {}: {}", 
                address, duration, reason);
        } catch (Exception e) {
            logger.error("Error adding temporary blacklist entry for " + address, e);
        }
    }

    public void addBannedPattern(String pattern) {
        if (pattern == null || pattern.length() > maxPatternLength) {
            logger.warn("Invalid pattern: {}", pattern);
            return;
        }

        try {
            Pattern.compile(pattern); // Validate pattern
            bannedPatterns.add(pattern);
            logger.info("Added banned pattern: {}", pattern);
        } catch (Exception e) {
            logger.error("Error adding banned pattern: " + pattern, e);
        }
    }

    public boolean isBlacklisted(InetAddress address) {
        // Check permanent blacklist
        if (permanentBlacklist.contains(address)) {
            updateStats("permanent");
            return true;
        }

        // Check temporary blacklist
        Long expiryTime = temporaryBlacklist.getIfPresent(address);
        if (expiryTime != null) {
            if (System.currentTimeMillis() < expiryTime) {
                updateStats("temporary");
                return true;
            } else {
                temporaryBlacklist.invalidate(address);
                blacklistEntries.remove(address);
            }
        }

        return false;
    }

    public boolean matchesPattern(String input) {
        if (input == null) return false;

        for (String pattern : bannedPatterns) {
            try {
                if (Pattern.matches(pattern, input)) {
                    updateStats("pattern");
                    return true;
                }
            } catch (Exception e) {
                logger.error("Error matching pattern: " + pattern, e);
            }
        }
        return false;
    }

    private void updateStats(String type) {
        blockStats.computeIfAbsent(type, k -> new AtomicInteger()).incrementAndGet();
    }

    private void logEvent(String type, InetAddress address, String reason) {
        BlacklistEvent event = new BlacklistEvent(type, address, reason);
        recentEvents.offer(event);

        // Maintain maximum size
        while (recentEvents.size() > maxRecentEvents) {
            recentEvents.poll();
        }
    }

    private void startMaintenanceTasks() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactoryBuilder()
                .setNameFormat("blacklist-maintenance-%d")
                .setDaemon(true)
                .build()
        );

        // Clean up expired entries
        executor.scheduleAtFixedRate(() -> {
            try {
                cleanupExpiredEntries();
            } catch (Exception e) {
                logger.error("Error cleaning up blacklist entries", e);
            }
        }, 1, 1, TimeUnit.HOURS);

        // Backup blacklist data
        executor.scheduleAtFixedRate(() -> {
            try {
                backupBlacklistData();
            } catch (Exception e) {
                logger.error("Error backing up blacklist data", e);
            }
        }, 1, 24, TimeUnit.HOURS);
    }

    private void cleanupExpiredEntries() {
        long now = System.currentTimeMillis();
        blacklistEntries.entrySet().removeIf(entry -> {
            BlacklistEntry blacklistEntry = entry.getValue();
            return blacklistEntry.expiryTime > 0 && blacklistEntry.expiryTime < now;
        });
    }

    private void backupBlacklistData() {
        // Implementation for backing up blacklist data
        logger.info("Backing up blacklist data...");
    }

    private static class BlacklistEntry {
        private final InetAddress address;
        private final String reason;
        private final long expiryTime; // -1 for permanent

        public BlacklistEntry(InetAddress address, String reason, long expiryTime) {
            this.address = address;
            this.reason = reason;
            this.expiryTime = expiryTime;
        }
    }

    private static class BlacklistEvent {
        private final String type;
        private final InetAddress address;
        private final String reason;
        private final long timestamp;

        public BlacklistEvent(String type, InetAddress address, String reason) {
            this.type = type;
            this.address = address;
            this.reason = reason;
            this.timestamp = System.currentTimeMillis();
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        
        stats.put("permanent_entries", permanentBlacklist.size());
        stats.put("temporary_entries", temporaryBlacklist.size());
        stats.put("banned_patterns", bannedPatterns.size());
        
        Map<String, Integer> blockCounts = new HashMap<>();
        blockStats.forEach((type, count) -> 
            blockCounts.put(type, count.get()));
        stats.put("block_counts", blockCounts);
        
        return stats;
    }

    public List<BlacklistEvent> getRecentEvents() {
        return new ArrayList<>(recentEvents);
    }

    public Optional<BlacklistEntry> getEntry(InetAddress address) {
        return Optional.ofNullable(blacklistEntries.get(address));
    }
}