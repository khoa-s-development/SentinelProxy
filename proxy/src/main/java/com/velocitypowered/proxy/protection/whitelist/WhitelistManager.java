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
 * Current Date and Time (UTC): 2025-06-14 09:33:15
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.whitelist;

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

public class WhitelistManager {
    private static final Logger logger = LogManager.getLogger(WhitelistManager.class);

    // Whitelist collections
    private final Set<InetAddress> permanentWhitelist;
    private final Cache<InetAddress, Long> temporaryWhitelist;
    private final Set<String> whitelistedPatterns;
    private final Map<InetAddress, WhitelistEntry> whitelistEntries;

    // Statistics tracking
    private final Map<String, AtomicInteger> allowStats;
    private final Queue<WhitelistEvent> recentEvents;

    // Configuration
    private final int maxPatternLength;
    private final Duration defaultWhitelistDuration;
    private final int maxRecentEvents;
    private final int maxEntriesPerIP;

    public WhitelistManager() {
        // Initialize collections
        this.permanentWhitelist = ConcurrentHashMap.newKeySet();
        this.temporaryWhitelist = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build();
        this.whitelistedPatterns = ConcurrentHashMap.newKeySet();
        this.whitelistEntries = new ConcurrentHashMap<>();

        // Initialize statistics
        this.allowStats = new ConcurrentHashMap<>();
        this.recentEvents = new ConcurrentLinkedQueue<>();

        // Load configuration
        this.maxPatternLength = 256;
        this.defaultWhitelistDuration = Duration.ofDays(30);
        this.maxRecentEvents = 1000;
        this.maxEntriesPerIP = 5;

        // Start maintenance tasks
        startMaintenanceTasks();
    }

    public void whitelistPermanently(InetAddress address, String reason) {
        try {
            permanentWhitelist.add(address);
            WhitelistEntry entry = new WhitelistEntry(address, reason, -1);
            whitelistEntries.put(address, entry);

            logEvent("PERMANENT", address, reason);
            logger.info("Permanently whitelisted {}: {}", address, reason);
        } catch (Exception e) {
            logger.error("Error adding permanent whitelist entry for " + address, e);
        }
    }

    public void whitelistTemporarily(InetAddress address, Duration duration, String reason) {
        try {
            long expiryTime = System.currentTimeMillis() + duration.toMillis();
            temporaryWhitelist.put(address, expiryTime);
            WhitelistEntry entry = new WhitelistEntry(address, reason, expiryTime);
            whitelistEntries.put(address, entry);

            logEvent("TEMPORARY", address, reason);
            logger.info("Temporarily whitelisted {} for {}: {}", 
                address, duration, reason);
        } catch (Exception e) {
            logger.error("Error adding temporary whitelist entry for " + address, e);
        }
    }

    public void addWhitelistedPattern(String pattern) {
        if (pattern == null || pattern.length() > maxPatternLength) {
            logger.warn("Invalid pattern: {}", pattern);
            return;
        }

        try {
            Pattern.compile(pattern); // Validate pattern
            whitelistedPatterns.add(pattern);
            logger.info("Added whitelisted pattern: {}", pattern);
        } catch (Exception e) {
            logger.error("Error adding whitelisted pattern: " + pattern, e);
        }
    }

    public boolean isWhitelisted(InetAddress address) {
        // Check permanent whitelist
        if (permanentWhitelist.contains(address)) {
            updateStats("permanent");
            return true;
        }

        // Check temporary whitelist
        Long expiryTime = temporaryWhitelist.getIfPresent(address);
        if (expiryTime != null) {
            if (System.currentTimeMillis() < expiryTime) {
                updateStats("temporary");
                return true;
            } else {
                temporaryWhitelist.invalidate(address);
                whitelistEntries.remove(address);
            }
        }

        return false;
    }

    public boolean matchesPattern(String input) {
        if (input == null) return false;

        for (String pattern : whitelistedPatterns) {
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
        allowStats.computeIfAbsent(type, k -> new AtomicInteger()).incrementAndGet();
    }

    private void logEvent(String type, InetAddress address, String reason) {
        WhitelistEvent event = new WhitelistEvent(type, address, reason);
        recentEvents.offer(event);

        // Maintain maximum size
        while (recentEvents.size() > maxRecentEvents) {
            recentEvents.poll();
        }
    }

    private void startMaintenanceTasks() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactoryBuilder()
                .setNameFormat("whitelist-maintenance-%d")
                .setDaemon(true)
                .build()
        );

        // Clean up expired entries
        executor.scheduleAtFixedRate(() -> {
            try {
                cleanupExpiredEntries();
            } catch (Exception e) {
                logger.error("Error cleaning up whitelist entries", e);
            }
        }, 1, 1, TimeUnit.HOURS);

        // Backup whitelist data
        executor.scheduleAtFixedRate(() -> {
            try {
                backupWhitelistData();
            } catch (Exception e) {
                logger.error("Error backing up whitelist data", e);
            }
        }, 1, 24, TimeUnit.HOURS);
    }

    private void cleanupExpiredEntries() {
        long now = System.currentTimeMillis();
        whitelistEntries.entrySet().removeIf(entry -> {
            WhitelistEntry whitelistEntry = entry.getValue();
            return whitelistEntry.expiryTime > 0 && whitelistEntry.expiryTime < now;
        });
    }

    private void backupWhitelistData() {
        // Implementation for backing up whitelist data
        logger.info("Backing up whitelist data...");
    }

    private static class WhitelistEntry {
        private final InetAddress address;
        private final String reason;
        private final long expiryTime; // -1 for permanent

        public WhitelistEntry(InetAddress address, String reason, long expiryTime) {
            this.address = address;
            this.reason = reason;
            this.expiryTime = expiryTime;
        }
    }

    private static class WhitelistEvent {
        private final String type;
        private final InetAddress address;
        private final String reason;
        private final long timestamp;

        public WhitelistEvent(String type, InetAddress address, String reason) {
            this.type = type;
            this.address = address;
            this.reason = reason;
            this.timestamp = System.currentTimeMillis();
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        
        stats.put("permanent_entries", permanentWhitelist.size());
        stats.put("temporary_entries", temporaryWhitelist.size());
        stats.put("whitelisted_patterns", whitelistedPatterns.size());
        
        Map<String, Integer> allowCounts = new HashMap<>();
        allowStats.forEach((type, count) -> 
            allowCounts.put(type, count.get()));
        stats.put("allow_counts", allowCounts);
        
        return stats;
    }

    public List<WhitelistEvent> getRecentEvents() {
        return new ArrayList<>(recentEvents);
    }

    public Optional<WhitelistEntry> getEntry(InetAddress address) {
        return Optional.ofNullable(whitelistEntries.get(address));
    }
}