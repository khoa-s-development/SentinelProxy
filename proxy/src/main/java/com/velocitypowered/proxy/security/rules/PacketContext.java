/*
 * Copyright (C) 2018-2023 Velocity Contributors
 * Current Date and Time (UTC): 2025-06-13 18:23:41
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security.rules;

import com.velocitypowered.api.event.connection.ConnectionHandshakeEvent;
import java.net.InetAddress;

public class ConnectionContext extends SecurityContext {
    private final ConnectionHandshakeEvent event;
    private boolean denied;

    public ConnectionContext(ConnectionHandshakeEvent event) {
        this.event = event;
        this.denied = false;
    }

    @Override
    public InetAddress getAddress() {
        return event.getConnection().getRemoteAddress().getAddress();
    }

    public int getProtocolVersion() {
        return event.getConnection().gpackage com.velocitypowered.proxy.security.rules;

import com.velocitypowered.proxy.protocol.MinecraftPacket;
import io.netty.channel.ChannelHandlerContext;

public class PacketContext extends SecurityContext {
    private final ChannelHandlerContext channelContext;
    private final MinecraftPacket packet;
    private final long timestamp;

    public PacketContext(ChannelHandlerContext ctx, MinecraftPacket packet) {
        this.channelContext = ctx;
        this.packet = packet;
        this.timestamp = System.currentTimeMillis();
    }

    public ChannelHandlerContext getChannelContext() {
        return channelContext;
    }

    public MinecraftPacket getPacket() {
        return packet;
    }

    public long getTimestamp() {
        return timestamp;
    }
}etProtocolVersion().getProtocol();
    }

    public void deny(String reason) {
        this.denied = true;
        this.reason = reason;
    }

    public boolean isDenied() {
        return denied;
    }
}