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

package com.velocitypowered.api.proxy.messages;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;

/**
 * Represents something that can be sent plugin messages.
 */
public interface ChannelMessageSink {

  /**
   * Sends a plugin message to this target.
   *
   * @param identifier the channel identifier to send the message on
   * @param data the data to send
   * @return whether or not the message could be sent
   */
  boolean sendPluginMessage(@NotNull ChannelIdentifier identifier, byte @NotNull[] data);

  /**
   * Sends a plugin message to this target.
   *
   * <pre>
   *   final ChannelMessageSink target;
   *   final ChannelIdentifier identifier;
   *   final boolean result = target.sendPluginMessage(identifier, (output) -> {
   *     output.writeUTF("some input");
   *     output.writeInt(1);
   *   });
   * </pre>
   *
   * @param identifier the channel identifier to send the message on
   * @param dataEncoder the encoder of the data to be sent
   * @return whether the message could be sent
   */
  @ApiStatus.Experimental
  boolean sendPluginMessage(
          @NotNull ChannelIdentifier identifier,
          @NotNull PluginMessageEncoder dataEncoder);
}
