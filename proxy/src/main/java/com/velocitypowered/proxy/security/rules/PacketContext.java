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
 *
 * Current Date and Time (UTC - YYYY-MM-DD HH:MM:SS formatted): 2025-06-14 13:30:48
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security.rules;

import com.velocitypowered.api.event.connection.ConnectionHandshakeEvent;
import com.velocitypowered.proxy.connection.MinecraftConnection;
import com.velocitypowered.proxy.connection.client.InitialInboundConnection;
import com.velocitypowered.proxy.protocol.packet.PacketEvent;
import java.net.InetSocketAddress;

public class PacketContext {
    private final PacketEvent event;
    private final MinecraftConnection connection;
    private final String clientAddress;
    private final String serverAddress;

    public PacketContext(PacketEvent event) {
        this.event = event;
        this.connection = event.getConnection();
        this.clientAddress = connection.getRemoteAddress().toString();
        this.serverAddress = connection.getVirtualHost().map(InetSocketAddress::getHostString).orElse("");
    }

    public PacketEvent getEvent() {
        return event;
    }
    public Object getPacket() {
        return event.getPacket();
    }
    
    public String getPacketType() {
        return event.getType();
    }
    
    public long getTimestamp() {
        return event.getTimestamp();
    }
}
    public MinecraftConnection getConnection() {
        return connection;
    }

    public String getClientAddress() {
        return clientAddress;
    }

    public String getServerAddress() {
        return serverAddress;
    }
    
    public InitialInboundConnection getInitialConnection() {
        if (connection instanceof InitialInboundConnection) {
            return (InitialInboundConnection) connection;
        }
        return null;
    }

    public ConnectionHandshakeEvent getHandshakeEvent() {
        InitialInboundConnection initial = getInitialConnection();
        return initial != null ? initial.getHandshakeEvent() : null;
    }
}