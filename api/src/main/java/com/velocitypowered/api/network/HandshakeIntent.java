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
 * Represents the ClientIntent of a client in the Handshake state.
 */
public enum HandshakeIntent {
  STATUS(1),
  LOGIN(2),
  TRANSFER(3);

  private final int id;

  HandshakeIntent(int id) {
    this.id = id;
  }

  public int id() {
    return this.id;
  }

  /**
   * Obtain the HandshakeIntent by ID.
   *
   * @param id the intent id
   * @return the HandshakeIntent desired
   */
  public static HandshakeIntent getById(int id) {
    return switch (id) {
      case 1 -> STATUS;
      case 2 -> LOGIN;
      case 3 -> TRANSFER;
      default -> null;
    };
  }
}
