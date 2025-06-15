package com.velocitypowered.proxy.protocol.packet;

public class PacketEvent {
    private final Object packet;  // hoặc type phù hợp cho packet
    private final long timestamp;
    private final String type;

    public PacketEvent(Object packet, String type) {
        this.packet = packet;
        this.type = type;
        this.timestamp = System.currentTimeMillis();
    }

    public Object getPacket() {
        return packet;
    }

    public String getType() {
        return type;
    }

    public long getTimestamp() {
        return timestamp;
    }
}