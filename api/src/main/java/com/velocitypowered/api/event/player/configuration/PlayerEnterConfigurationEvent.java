/*
 * Copyright (C) 2024 Velocity Contributors
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

package com.velocitypowered.api.event.player.configuration;

import com.velocitypowered.api.event.annotation.AwaitingEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ServerConnection;
import org.jetbrains.annotations.NotNull;

/**
 * This event is executed when a player is about to enter the configuration state.
 * It is <b>not</b> called for the initial configuration of a player after login.
 * <p>Velocity will wait for this event before asking the client to enter configuration state.
 * However due to backend server being unable to keep the connection alive during state changes,
 * Velocity will only wait for a maximum of 5 seconds.</p>
 *
 * @param player The player who is about to enter configuration state.
 * @param server The server that wants to reconfigure the player.
 * @since 3.3.0
 * @sinceMinecraft 1.20.2
 */
@AwaitingEvent
public record PlayerEnterConfigurationEvent(@NotNull Player player, ServerConnection server) {
}
