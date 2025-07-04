/*
 * Copyright (C) 2018-2021 Velocity Contributors
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

package com.velocitypowered.api.event.connection;

import com.google.common.base.Preconditions;
import com.velocitypowered.api.network.HandshakeIntent;
import com.velocitypowered.api.proxy.InboundConnection;

/**
 * This event is fired when a handshake is established between a client and the proxy.
 * Velocity will fire this event asynchronously and will not wait for it to complete before
 * handling the connection.
 */
public final class ConnectionHandshakeEvent {

  private final InboundConnection connection;
  private final HandshakeIntent intent;

  public ConnectionHandshakeEvent(InboundConnection connection, HandshakeIntent intent) {
    this.connection = Preconditions.checkNotNull(connection, "connection");
    this.intent = Preconditions.checkNotNull(intent, "intent");
  }

  /**
   * This method is only retained to avoid breaking plugins
   * that have not yet updated their integration tests.
   *
   * @param connection the inbound connection
   * @deprecated use {@link #ConnectionHandshakeEvent(InboundConnection, HandshakeIntent)}
   */
  @Deprecated(forRemoval = true)
  public ConnectionHandshakeEvent(InboundConnection connection) {
    this.connection = Preconditions.checkNotNull(connection, "connection");
    this.intent = HandshakeIntent.LOGIN;
  }

  public InboundConnection getConnection() {
    return connection;
  }

  public HandshakeIntent getIntent() {
    return this.intent;
  }

  @Override
  public String toString() {
    return "ConnectionHandshakeEvent{"
        + "connection=" + connection
        + ", intent=" + intent
        + '}';
  }
}
