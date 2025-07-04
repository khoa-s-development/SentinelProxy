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

import com.velocitypowered.api.network.ProtocolState;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ServerConnection;
import org.jetbrains.annotations.NotNull;

/**
 * This event is executed when a player has finished the configuration state.
 * <p>From this moment on, the {@link Player#getProtocolState()} method
 * will return {@link ProtocolState#PLAY}.</p>
 *
 * @param player The player who has finished the configuration state.
 * @param server The server that has (re-)configured the player.
 * @since 3.3.0
 * @sinceMinecraft 1.20.2
 */
public record PlayerFinishedConfigurationEvent(@NotNull Player player, @NotNull ServerConnection server) {
}
