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
 */

package com.velocitypowered.proxy.protection.storage;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import java.net.InetAddress;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class SecurityStorage {
    private final Cache<InetAddress, SecurityEntry> securityCache;
    private final Map<UUID, SecurityProfile> profiles;
    
    public SecurityStorage() {
        this.securityCache = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();
            
        this.profiles = new ConcurrentHashMap<>();
    }

    public void addSecurityEvent(InetAddress address, String type) {
        SecurityEntry entry = securityCache.getIfPresent(address);
        if (entry == null) {
            entry = new SecurityEntry();
        }
        entry.addEvent(type);
        securityCache.put(address, entry);
    }

    public Optional<SecurityEntry> getSecurityEntry(InetAddress address) {
        return Optional.ofNullable(securityCache.getIfPresent(address));
    }

    public void addProfile(UUID playerId, SecurityProfile profile) {
        profiles.put(playerId, profile);
    }

    public Optional<SecurityProfile> getProfile(UUID playerId) {
        return Optional.ofNullable(profiles.get(playerId));
    }

    public static class SecurityEntry {
        private final Map<String, Integer> eventCounts;
        private final Instant created;
        private Instant lastUpdated;

        public SecurityEntry() {
            this.eventCounts = new ConcurrentHashMap<>();
            this.created = Instant.now();
            this.lastUpdated = Instant.now();
        }

        public void addEvent(String type) {
            eventCounts.compute(type, (k, v) -> v == null ? 1 : v + 1);
            this.lastUpdated = Instant.now();
        }

        public int getEventCount(String type) {
            return eventCounts.getOrDefault(type, 0);
        }

        public Instant getCreated() {
            return created;
        }

        public Instant getLastUpdated() {
            return lastUpdated;
        }
    }

    public static class SecurityProfile {
        private final UUID playerId;
        private final Map<String, Object> attributes;
        private Instant lastLogin;

        public SecurityProfile(UUID playerId) {
            this.playerId = playerId;
            this.attributes = new ConcurrentHashMap<>();
            this.lastLogin = Instant.now();
        }

        public void setAttribute(String key, Object value) {
            attributes.put(key, value);
        }

        public Optional<Object> getAttribute(String key) {
            return Optional.ofNullable(attributes.get(key));
        }

        public void updateLastLogin() {
            this.lastLogin = Instant.now();
        }

        public UUID getPlayerId() {
            return playerId;
        }

        public Instant getLastLogin() {
            return lastLogin;
        }
    }
}