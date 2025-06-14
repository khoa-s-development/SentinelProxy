package com.velocitypowered.proxy.protocol.packet;

import com.velocitypowered.proxy.connection.MinecraftSessionHandler;
import com.velocitypowered.proxy.protocol.MinecraftPacket;
import com.velocitypowered.proxy.protocol.ProtocolUtils;
import io.netty.buffer.ByteBuf;

public class LoginPacket implements MinecraftPacket {
    private String username;
    private byte[] verifyToken;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public byte[] getVerifyToken() {
        return verifyToken;
    }

    public void setVerifyToken(byte[] verifyToken) {
        this.verifyToken = verifyToken;
    }

    @Override
    public void decode(ByteBuf buf, ProtocolUtils.Direction direction, int protocolVersion) {
        username = ProtocolUtils.readString(buf);
        if (buf.readableBytes() > 0) {
            verifyToken = new byte[buf.readableBytes()];
            buf.readBytes(verifyToken);
        }
    }

    @Override
    public void encode(ByteBuf buf, ProtocolUtils.Direction direction, int protocolVersion) {
        ProtocolUtils.writeString(buf, username);
        if (verifyToken != null) {
            buf.writeBytes(verifyToken);
        }
    }

    @Override
    public boolean handle(MinecraftSessionHandler handler) {
        return handler.handle(this);
    }
}