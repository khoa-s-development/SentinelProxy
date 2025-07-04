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

package com.velocitypowered.api.proxy.messages;

import com.google.common.io.ByteArrayDataOutput;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;

/**
 * A data encoder to be sent via a plugin message.
 *
 * @since 3.3.0
 */
@FunctionalInterface
@ApiStatus.Experimental
public interface PluginMessageEncoder {

  /**
   * Encodes data into a {@link ByteArrayDataOutput} to be transmitted by plugin messages.
   *
   * @param output the {@link ByteArrayDataOutput} provided
   */
  void encode(@NotNull ByteArrayDataOutput output);
}
