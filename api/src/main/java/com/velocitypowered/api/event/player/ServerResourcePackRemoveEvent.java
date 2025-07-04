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

package com.velocitypowered.api.event.player;

import com.google.common.base.Preconditions;
import com.velocitypowered.api.event.ResultedEvent;
import com.velocitypowered.api.event.annotation.AwaitingEvent;
import com.velocitypowered.api.proxy.ServerConnection;
import java.util.UUID;
import org.checkerframework.checker.nullness.qual.MonotonicNonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * This event is fired when the downstream server tries to remove a resource pack from player
 * or clear all of them. The proxy will wait on this event to finish before forwarding the
 * action to the user. If this event is denied, no resource packs will be removed from player.
 */
@AwaitingEvent
public class ServerResourcePackRemoveEvent implements ResultedEvent<ResultedEvent.GenericResult> {

  private GenericResult result;
  private final @MonotonicNonNull UUID packId;
  private final ServerConnection serverConnection;

  /**
   * Instantiates this event.
   */
  public ServerResourcePackRemoveEvent(UUID packId, ServerConnection serverConnection) {
    this.result = ResultedEvent.GenericResult.allowed();
    this.packId = packId;
    this.serverConnection = serverConnection;
  }

  /**
   * Returns the id of the resource pack, if it's null all the resource packs
   * from player will be cleared.
   *
   * @return the id
   */
  @Nullable
  public UUID getPackId() {
    return packId;
  }

  /**
   * Returns the server that tries to remove a resource pack from player or clear all of them.
   *
   * @return the server connection
   */
  public ServerConnection getServerConnection() {
    return serverConnection;
  }

  @Override
  public GenericResult getResult() {
    return this.result;
  }

  @Override
  public void setResult(GenericResult result) {
    this.result = Preconditions.checkNotNull(result, "result");
  }
}
