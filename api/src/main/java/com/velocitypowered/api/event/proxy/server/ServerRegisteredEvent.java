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

package com.velocitypowered.api.event.proxy.server;

import com.google.common.base.Preconditions;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import org.jetbrains.annotations.NotNull;

/**
 * This event is fired by the proxy after a backend server is registered to the server map.
 * Currently, it may occur when a server is registered dynamically at runtime or when a server is
 * replaced due to configuration reload.
 *
 * @see com.velocitypowered.api.proxy.ProxyServer#registerServer(ServerInfo)
 *
 * @param registeredServer A {@link RegisteredServer} that has been registered.
 * @since 3.3.0
 */
public record ServerRegisteredEvent(@NotNull RegisteredServer registeredServer) {
  public ServerRegisteredEvent {
    Preconditions.checkNotNull(registeredServer, "registeredServer");
  }
}
