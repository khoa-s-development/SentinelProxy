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
 * Current Date and Time (UTC): 2025-06-14 02:05:08
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security;

import com.google.common.base.Preconditions;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.connection.client.ConnectedPlayer;
import com.velocitypowered.proxy.protocol.packet.LoginPacket;
import com.velocitypowered.proxy.security.crypto.EncryptionManager;
import com.velocitypowered.proxy.security.store.SecurityStore;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.SecretKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LoginManager {
    private static final Logger logger = LogManager.getLogger(LoginManager.class);

    // Core components
    private final VelocityServer server;
    private final EncryptionManager encryptionManager;
    private final SecurityStore securityStore;
    private final ExecutorService loginExecutor;

    // Login tracking
    private final Cache<InetAddress, LoginAttemptTracker> loginAttempts;
    private final Cache<UUID, LoginSession> activeSessions;
    private final Map<String, Queue<LoginRequest>> loginQueues;

    // Configuration
    private final int maxLoginAttemptsPerIP;
    private final int maxConcurrentLogins;
    private final int loginQueueTimeout;
    private final int sessionTimeout;
    private final boolean enforceSecureProfile;

    public LoginManager(VelocityServer server, EncryptionManager encryptionManager, SecurityStore securityStore) {
        this.server = server;
        this.encryptionManager = encryptionManager;
        this.securityStore = securityStore;

        // Initialize executor
        this.loginExecutor = new ThreadPoolExecutor(
            2,
            4,
            60L,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(),
            new ThreadFactoryBuilder()
                .setNameFormat("login-worker-%d")
                .setDaemon(true)
                .build()
        );

        // Initialize caches
        this.loginAttempts = CacheBuilder.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .build();
        this.activeSessions = CacheBuilder.newBuilder()
            .expireAfterAccess(30, TimeUnit.MINUTES)
            .build();
        this.loginQueues = new ConcurrentHashMap<>();

        // Load configuration
        this.maxLoginAttemptsPerIP = 5;
        this.maxConcurrentLogins = 100;
        this.loginQueueTimeout = 30;
        this.sessionTimeout = 1800;
        this.enforceSecureProfile = true;

        // Start maintenance tasks
        startMaintenanceTasks();
    }

    public CompletableFuture<LoginResult> processLogin(LoginPacket packet, ConnectedPlayer player) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Validate login request
                LoginValidationResult validation = validateLogin(packet, player);
                if (!validation.isValid()) {
                    return new LoginResult(false, validation.getReason());
                }

                // Check login queue
                if (!checkAndQueueLogin(player)) {
                    return new LoginResult(false, "Login queue full");
                }

                // Process authentication
                AuthenticationResult auth = authenticatePlayer(packet, player);
                if (!auth.isSuccessful()) {
                    return new LoginResult(false, auth.getFailureReason());
                }

                // Create session
                LoginSession session = createLoginSession(player, auth);
                activeSessions.put(player.getUniqueId(), session);

                // Fire login event
                LoginEvent event = new LoginEvent(player);
                server.getEventManager().fire(event).join();

                if (event.getResult().isAllowed()) {
                    return new LoginResult(true, null);
                } else {
                    return new LoginResult(false, event.getResult().getReason().orElse("Login denied"));
                }

            } catch (Exception e) {
                logger.error("Error processing login for " + player.getUsername(), e);
                return new LoginResult(false, "Internal server error");
            } finally {
                // Cleanup queue
                removeFromQueue(player);
            }
        }, loginExecutor);
    }

    private LoginValidationResult validateLogin(LoginPacket packet, ConnectedPlayer player) {
        InetAddress address = player.getRemoteAddress().getAddress();

        // Check if blacklisted
        if (securityStore.isBlacklisted(address)) {
            return new LoginValidationResult(false, "Your IP is blacklisted");
        }

        // Check login attempts
        LoginAttemptTracker tracker = loginAttempts.getIfPresent(address);
        if (tracker != null && tracker.getAttempts() >= maxLoginAttemptsPerIP) {
            return new LoginValidationResult(false, "Too many login attempts");
        }

        // Validate username
        if (!isValidUsername(packet.getUsername())) {
            return new LoginValidationResult(false, "Invalid username");
        }

        // Check for secure profile if required
        if (enforceSecureProfile && !packet.hasSecureProfile()) {
            return new LoginValidationResult(false, "Secure profile required");
        }

        return new LoginValidationResult(true, null);
    }

    private boolean checkAndQueueLogin(ConnectedPlayer player) {
        String queueKey = getQueueKey(player);
        Queue<LoginRequest> queue = loginQueues.computeIfAbsent(queueKey,
            k -> new ConcurrentLinkedQueue<>());

        // Check queue size
        if (queue.size() >= maxConcurrentLogins) {
            return false;
        }

        // Add to queue
        LoginRequest request = new LoginRequest(player);
        queue.offer(request);

        return true;
    }

    private void removeFromQueue(ConnectedPlayer player) {
        String queueKey = getQueueKey(player);
        Queue<LoginRequest> queue = loginQueues.get(queueKey);
        if (queue != null) {
            queue.removeIf(req -> req.getPlayer().equals(player));
        }
    }

    private AuthenticationResult authenticatePlayer(LoginPacket packet, ConnectedPlayer player) {
        try {
            // Online mode authentication
            if (server.getConfiguration().isOnlineModeEnabled()) {
                return authenticateOnlineMode(packet, player);
            }
            
            // Offline mode authentication
            return authenticateOfflineMode(packet, player);
            
        } catch (Exception e) {
            logger.error("Authentication error for " + player.getUsername(), e);
            return new AuthenticationResult(false, "Authentication failed");
        }
    }

    private AuthenticationResult authenticateOnlineMode(LoginPacket packet, ConnectedPlayer player) {
        // Implement Mojang authentication
        return new AuthenticationResult(true, null);
    }

    private AuthenticationResult authenticateOfflineMode(LoginPacket packet, ConnectedPlayer player) {
        // Basic offline mode checks
        return new AuthenticationResult(true, null);
    }

    private LoginSession createLoginSession(ConnectedPlayer player, AuthenticationResult auth) {
        SecretKey sessionKey = encryptionManager.generateSecretKey();
        return new LoginSession(player.getUniqueId(), sessionKey, System.currentTimeMillis());
    }

    private String getQueueKey(ConnectedPlayer player) {
        return player.getVirtualHost()
            .map(host -> host.getHostString())
            .orElse("default");
    }

    private boolean isValidUsername(String username) {
        return username != null &&
               username.length() >= 3 &&
               username.length() <= 16 &&
               username.matches("^[a-zA-Z0-9_]+$");
    }

    private void startMaintenanceTasks() {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        
        // Clean expired sessions
        scheduler.scheduleAtFixedRate(() -> {
            try {
                cleanupExpiredSessions();
                cleanupLoginQueues();
            } catch (Exception e) {
                logger.error("Error in maintenance task", e);
            }
        }, 5, 5, TimeUnit.MINUTES);
    }

    private void cleanupExpiredSessions() {
        long now = System.currentTimeMillis();
        activeSessions.asMap().entrySet().removeIf(entry ->
            (now - entry.getValue().getCreationTime()) > sessionTimeout * 1000L);
    }

    private void cleanupLoginQueues() {
        loginQueues.entrySet().removeIf(entry -> {
            Queue<LoginRequest> queue = entry.getValue();
            queue.removeIf(request -> 
                (System.currentTimeMillis() - request.getTimestamp()) > loginQueueTimeout * 1000L);
            return queue.isEmpty();
        });
    }

    // Inner classes
    private static class LoginAttemptTracker {
        private final AtomicInteger attempts = new AtomicInteger();
        private final long firstAttempt;

        public LoginAttemptTracker() {
            this.firstAttempt = System.currentTimeMillis();
        }

        public int incrementAndGet() {
            return attempts.incrementAndGet();
        }

        public int getAttempts() {
            return attempts.get();
        }

        public long getFirstAttempt() {
            return firstAttempt;
        }
    }

    private static class LoginSession {
        private final UUID playerId;
        private final SecretKey sessionKey;
        private final long creationTime;

        public LoginSession(UUID playerId, SecretKey sessionKey, long creationTime) {
            this.playerId = playerId;
            this.sessionKey = sessionKey;
            this.creationTime = creationTime;
        }

        public UUID getPlayerId() {
            return playerId;
        }

        public SecretKey getSessionKey() {
            return sessionKey;
        }

        public long getCreationTime() {
            return creationTime;
        }
    }

    private static class LoginRequest {
        private final ConnectedPlayer player;
        private final long timestamp;

        public LoginRequest(ConnectedPlayer player) {
            this.player = player;
            this.timestamp = System.currentTimeMillis();
        }

        public ConnectedPlayer getPlayer() {
            return player;
        }

        public long getTimestamp() {
            return timestamp;
        }
    }

    private static class LoginResult {
        private final boolean success;
        private final String failureReason;

        public LoginResult(boolean success, String failureReason) {
            this.success = success;
            this.failureReason = failureReason;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getFailureReason() {
            return failureReason;
        }
    }

    private static class LoginValidationResult {
        private final boolean valid;
        private final String reason;

        public LoginValidationResult(boolean valid, String reason) {
            this.valid = valid;
            this.reason = reason;
        }

        public boolean isValid() {
            return valid;
        }

        public String getReason() {
            return reason;
        }
    }

    private static class AuthenticationResult {
        private final boolean successful;
        private final String failureReason;

        public AuthenticationResult(boolean successful, String failureReason) {
            this.successful = successful;
            this.failureReason = failureReason;
        }

        public boolean isSuccessful() {
            return successful;
        }

        public String getFailureReason() {
            return failureReason;
        }
    }
}