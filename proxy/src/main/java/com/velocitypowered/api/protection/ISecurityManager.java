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

package com.velocitypowered.api.protection;

import com.velocitypowered.api.proxy.Player;
import java.net.InetAddress;
import java.util.Optional;
import java.util.UUID;

public interface ISecurityManager {
    /**
     * Checks if a connection should be allowed.
     *
     * @param address the IP address to check
     * @return true if the connection is allowed
     */
    boolean isConnectionAllowed(InetAddress address);

    /**
     * Checks if a player should be allowed to connect.
     *
     * @param player the player to check
     * @return true if the player is allowed
     */
    boolean isPlayerAllowed(Player player);

    /**
     * Gets the security profile for a player.
     *
     * @param playerId the UUID of the player
     * @return the security profile if found
     */
    Optional<SecurityProfile> getProfile(UUID playerId);

    /**
     * Adds a security event for an IP address.
     *
     * @param address the IP address
     * @param type the type of event
     */
    void addSecurityEvent(InetAddress address, String type);

    /**
     * Blacklists an IP address.
     *
     * @param address the IP to blacklist
     * @param duration duration in seconds
     */
    void blacklist(InetAddress address, int duration);

    /**
     * Whitelists an IP address.
     *
     * @param address the IP to whitelist
     */
    void whitelist(InetAddress address);

    /**
     * Checks if an IP is blacklisted.
     *
     * @param address the IP to check
     * @return true if blacklisted
     */
    boolean isBlacklisted(InetAddress address);

    /**
     * Gets the current security level.
     *
     * @return the security level
     */
    SecurityLevel getSecurityLevel();

    /**
     * Sets the security level.
     *
     * @param level the new security level
     */
    void setSecurityLevel(SecurityLevel level);

    enum SecurityLevel {
        LOW,
        MEDIUM,
        HIGH,
        EXTREME
    }

    interface SecurityProfile {
        UUID getPlayerId();
        int getViolationLevel();
        long getLastLoginTime();
        boolean isVerified();
    }
}