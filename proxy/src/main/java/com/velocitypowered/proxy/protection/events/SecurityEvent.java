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

package com.velocitypowered.proxy.protection.events;

import com.velocitypowered.api.event.ResultedEvent;
import com.velocitypowered.api.proxy.Player;
import java.net.InetAddress;
import java.time.Instant;
import net.kyori.adventure.text.Component;

public class SecurityEvent implements ResultedEvent<SecurityEvent.SecurityResult> {
    private final InetAddress address;
    private final String type;
    private final Instant timestamp;
    private final Player player;
    private SecurityResult result;

    public SecurityEvent(InetAddress address, String type, Player player) {
        this.address = address;
        this.type = type;
        this.timestamp = Instant.now();
        this.player = player;
        this.result = SecurityResult.allowed();
    }

    @Override
    public SecurityResult getResult() {
        return result;
    }

    @Override
    public void setResult(SecurityResult result) {
        this.result = result;
    }

    public InetAddress getAddress() {
        return address;
    }

    public String getType() {
        return type;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public Player getPlayer() {
        return player;
    }

    public static class SecurityResult implements ResultedEvent.Result {
        private final boolean allowed;
        private final Component reason;

        private SecurityResult(boolean allowed, Component reason) {
            this.allowed = allowed;
            this.reason = reason;
        }

        public static SecurityResult allowed() {
            return new SecurityResult(true, null);
        }

        public static SecurityResult denied(Component reason) {
            return new SecurityResult(false, reason);
        }

        public boolean isAllowed() {
            return allowed;
        }

        public Component getReason() {
            return reason;
        }
    }
}