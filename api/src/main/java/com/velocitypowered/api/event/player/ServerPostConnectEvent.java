/*
 * Copyright (C) 2020-2021 Velocity Contributors
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

package com.velocitypowered.api.event.player;

import com.google.common.base.Preconditions;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Fired after the player has connected to a server. The server the player is now connected to is
 * available in {@link Player#getCurrentServer()}. Velocity will not wait on this event to finish
 * firing.
 */
public class ServerPostConnectEvent {
  private final Player player;
  private final RegisteredServer previousServer;

  public ServerPostConnectEvent(Player player,
      @Nullable RegisteredServer previousServer) {
    this.player = Preconditions.checkNotNull(player, "player");
    this.previousServer = previousServer;
  }

  /**
   * Returns the player that has completed the connection to the server.
   *
   * @return the player
   */
  public Player getPlayer() {
    return player;
  }

  /**
   * Returns the previous server the player was connected to. This is {@code null} if they were not
   * connected to another server beforehand (for instance, if the player has just joined the proxy).
   *
   * @return the previous server the player was connected to
   */
  public @Nullable RegisteredServer getPreviousServer() {
    return previousServer;
  }

  @Override
  public String toString() {
    return "ServerPostConnectEvent{"
        + "player=" + player
        + ", previousServer=" + previousServer
        + '}';
  }
}
