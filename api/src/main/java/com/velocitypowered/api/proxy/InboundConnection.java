/*
 * Copyright (C) 2018-2022 Velocity Contributors
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

package com.velocitypowered.api.proxy;

import com.velocitypowered.api.network.HandshakeIntent;
import com.velocitypowered.api.network.ProtocolState;
import com.velocitypowered.api.network.ProtocolVersion;
import java.net.InetSocketAddress;
import java.util.Optional;

/**
 * Represents an incoming connection to the proxy.
 */
public interface InboundConnection {

  /**
   * Returns the player's IP address.
   *
   * @return the player's IP
   */
  InetSocketAddress getRemoteAddress();

  /**
   * Returns the hostname that the user entered into the client, if applicable.
   * <br/>
   * This is partially processed, including removing a trailing dot, and discarding data after a null byte.

   * @return the hostname from the client
   */
  Optional<InetSocketAddress> getVirtualHost();

  /**
   * Returns the raw hostname that the client sent, if applicable.
   *
   * @return the raw hostname from the client
   */
  Optional<String> getRawVirtualHost();

  /**
   * Determine whether or not the player remains online.
   *
   * @return whether or not the player active
   */
  boolean isActive();

  /**
   * Returns the current protocol version this connection uses.
   *
   * @return the protocol version the connection uses
   */
  ProtocolVersion getProtocolVersion();

  /**
   * Returns the current protocol state of this connection.
   *
   * @return the protocol state of the connection
   */
  ProtocolState getProtocolState();

  /**
   * Returns the initial intent for the connection.
   *
   * @return the intent of the connection
   */
  HandshakeIntent getHandshakeIntent();
}
