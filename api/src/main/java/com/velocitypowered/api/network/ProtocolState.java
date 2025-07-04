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

package com.velocitypowered.api.network;

/**
 * Representation of the state of the protocol
 * in which a connection can be present.
 *
 * @since 3.3.0
 */
public enum ProtocolState {
  /**
   * Initial connection State.
   * <p>This status can be caused by a {@link HandshakeIntent#STATUS},
   * {@link HandshakeIntent#LOGIN} or {@link HandshakeIntent#TRANSFER} intent.</p>
   * If the intent is LOGIN or TRANSFER, the next state will be {@link #LOGIN},
   * otherwise, it will go to the {@link #STATUS} state.
   */
  HANDSHAKE,
  /**
   * Ping State of a connection.
   * <p>Connections with the {@link HandshakeIntent#STATUS} intent will pass through this state
   * and be disconnected after it requests the ping from the server
   * and the server responds with the respective ping.</p>
   */
  STATUS,
  /**
   * Authentication State of a connection.
   * <p>At this moment the player is authenticating with the authentication servers.</p>
   */
  LOGIN,
  /**
   * Configuration State of a connection.
   * <p>At this point the player allows the server to send information
   * such as resource packs and plugin messages, at the same time the player
   * will send his client brand and the respective plugin messages
   * if it is a modded client.</p>
   *
   * @sinceMinecraft 1.20.2
   */
  CONFIGURATION,
  /**
   * Game State of a connection.
   * <p>In this state is where the whole game runs, the server is able to change
   * the player's state to {@link #CONFIGURATION} as needed in versions 1.20.2 and higher.</p>
   */
  PLAY
}
