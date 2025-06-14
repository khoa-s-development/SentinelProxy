/*
 * Copyright (C) 2018-2023 Velocity Contributors
 * Current Date and Time (UTC): 2025-06-13 18:18:05
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security.store;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.velocitypowered.api.proxy.Player;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SecurityStore {
    private static final Logger logger = LogManager.getLogger(SecurityStore.class);

    // Rate limiting and throttling
    private final Cache<InetAddress, RateLimit> rateLimits;
    private final Cache<InetAddress, Integer> loginAttempts;
    private final Cache<UUID, Integer> commandAttempts;

    // Access control
    private final Map<InetAddress, AccessEntry> blacklist;
    private final Set<InetAddress> whitelist;
    private final Map<String, Set<String>> permissionGroups;

    // Session tracking
    private final Cache<String, SessionInfo> activeSessions;
    private final Cache<InetAddress, Set<UUID>> addressToPlayers;
    private final Cache<UUID, SecurityProfile> securityProfiles;

    // Configuration
    private final int maxLoginAttemptsPerIP;
    private final Duration loginThrottleTime;
    private final int maxCommandsPerSecond;
    private final Duration blacklistDuration;

    public SecurityStore() {
        // Initialize rate limiting caches
        this.rateLimits = CacheBuilder.newBuilder()
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .build();
        this.loginAttempts = CacheBuilder.newBuilder()
                .expireAfterWrite(10, TimeUnit.MINUTES)
                .build();
        this.commandAttempts = CacheBuilder.newBuilder()
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .build();

        // Initialize session tracking
        this.activeSessions = CacheBuilder.newBuilder()
                .expireAfterAccess(30, TimeUnit.MINUTES)
                .build();
        this.addressToPlayers = CacheBuilder.newBuilder()
                .expireAfterWrite(1, TimeUnit.HOURS)
                .build();
        this.securityProfiles = CacheBuilder.newBuilder()
                .expireAfterAccess(24, TimeUnit.HOURS)
                .build();

        // Initialize access control
        this.blacklist = new ConcurrentHashMap<>();
        this.whitelist = Collections.newSetFromMap(new ConcurrentHashMap<>());
        this.permissionGroups = new ConcurrentHashMap<>();

        // Set default configuration
        this.maxLoginAttemptsPerIP = 5;
        this.loginThrottleTime = Duration.ofMinutes(10);
        this.maxCommandsPerSecond = 10;
        this.blacklistDuration = Duration.ofHours(24);
    }

    // Rate limiting methods
    public boolean checkRateLimit(InetAddress address, String action) {
        RateLimit limit = rateLimits.getIfPresent(address);
        if (limit == null) {
            limit = new RateLimit();
            rateLimits.put(address, limit);
        }
        return limit.tryAcquire();
    }

    public void recordLoginAttempt(InetAddress address) {
        Integer attempts = loginAttempts.getIfPresent(address);
        if (attempts == null) {
            loginAttempts.put(address, 1);
        } else {
            loginAttempts.put(address, attempts + 1);
            if (attempts + 1 >= maxLoginAttemptsPerIP) {
                blacklist(address, blacklistDuration);
            }
        }
    }

    public boolean canLogin(InetAddress address) {
        Integer attempts = loginAttempts.getIfPresent(address);
        return attempts == null || attempts < maxLoginAttemptsPerIP;
    }

    // Access control methods
    public void blacklist(InetAddress address, Duration duration) {
        blacklist.put(address, new AccessEntry(duration));
        logger.info("Address {} has been blacklisted for {}", address, duration);
    }

    public void whitelist(InetAddress address) {
        whitelist.add(address);
        blacklist.remove(address);
        logger.info("Address {} has been whitelisted", address);
    }

    public boolean isBlacklisted(InetAddress address) {
        AccessEntry entry = blacklist.get(address);
        if (entry != null) {
            if (entry.hasExpired()) {
                blacklist.remove(address);
                return false;
            }
            return true;
        }
        return false;
    }

    public boolean isWhitelisted(InetAddress address) {
        return whitelist.contains(address);
    }

    // Session management
    public void createSession(Player player, String sessionId) {
        InetAddress address = player.getRemoteAddress().getAddress();
        UUID playerId = player.getUniqueId();

        // Record session
        activeSessions.put(sessionId, new SessionInfo(playerId, address));

        // Update address mapping
        Set<UUID> players = addressToPlayers.getIfPresent(address);
        if (players == null) {
            players = Collections.newSetFromMap(new ConcurrentHashMap<>());
            addressToPlayers.put(address, players);
        }
        players.add(playerId);

        // Create or update security profile
        SecurityProfile profile = securityProfiles.getIfPresent(playerId);
        if (profile == null) {
            profile = new SecurityProfile(playerId);
            securityProfiles.put(playerId, profile);
        }
        profile.recordLogin(address);
    }

    public void endSession(String sessionId) {
        SessionInfo info = activeSessions.getIfPresent(sessionId);
        if (info != null) {
            Set<UUID> players = addressToPlayers.getIfPresent(info.address);
            if (players != null) {
                players.remove(info.playerId);
                if (players.isEmpty()) {
                    addressToPlayers.invalidate(info.address);
                }
            }
            activeSessions.invalidate(sessionId);
        }
    }

    public Optional<SecurityProfile> getProfile(UUID playerId) {
        return Optional.ofNullable(securityProfiles.getIfPresent(playerId));
    }

    // Cleanup and maintenance
    public void cleanup() {
        // Remove expired blacklist entries
        blacklist.entrySet().removeIf(entry -> entry.getValue().hasExpired());

        // Log statistics
        if (logger.isDebugEnabled()) {
            logger.debug("Security store stats - Active sessions: {}, Blacklisted: {}, Whitelisted: {}",
                    activeSessions.size(), blacklist.size(), whitelist.size());
        }
    }

    // Inner classes
    private static class RateLimit {
        private final Queue<Long> timestamps = new LinkedList<>();
        private static final int WINDOW_SIZE = 10;
        private static final long WINDOW_TIME = TimeUnit.SECONDS.toMillis(1);

        public synchronized boolean tryAcquire() {
            long now = System.currentTimeMillis();
            while (!timestamps.isEmpty() && timestamps.peek() < now - WINDOW_TIME) {
                timestamps.poll();
            }
            if (timestamps.size() < WINDOW_SIZE) {
                timestamps.offer(now);
                return true;
            }
            return false;
        }
    }

    private static class AccessEntry {
        private final Instant expiry;

        public AccessEntry(Duration duration) {
            this.expiry = Instant.now().plus(duration);
        }

        public boolean hasExpired() {
            return Instant.now().isAfter(expiry);
        }
    }

    private static class SessionInfo {
        private final UUID playerId;
        private final InetAddress address;
        private final Instant created;

        public SessionInfo(UUID playerId, InetAddress address) {
            this.playerId = playerId;
            this.address = address;
            this.created = Instant.now();
        }
    }

    public static class SecurityProfile {
        private final UUID playerId;
        private final List<LoginRecord> loginHistory;
        private int violationLevel;
        private boolean verified;

        public SecurityProfile(UUID playerId) {
            this.playerId = playerId;
            this.loginHistory = new ArrayList<>();
            this.violationLevel = 0;
            this.verified = false;
        }

        public void recordLogin(InetAddress address) {
            loginHistory.add(new LoginRecord(address));
            if (loginHistory.size() > 10) {
                loginHistory.remove(0);
            }
        }

        public void incrementViolations() {
            violationLevel++;
        }

        public void setVerified(boolean verified) {
            this.verified = verified;
        }

        public UUID getPlayerId() {
            return playerId;
        }

        public int getViolationLevel() {
            return violationLevel;
        }

        public boolean isVerified() {
            return verified;
        }

        public List<LoginRecord> getLoginHistory() {
            return Collections.unmodifiableList(loginHistory);
        }
    }

    private static class LoginRecord {
        private final InetAddress address;
        private final Instant timestamp;

        public LoginRecord(InetAddress address) {
            this.address = address;
            this.timestamp = Instant.now();
        }
    }
}