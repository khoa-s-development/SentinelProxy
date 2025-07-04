package com.velocitypowered.proxy.connection.antiddos;

public class AntiDdosConfig {
    public int maxConnectionsPerIp = 5;
    public int maxPacketsPerSecond = 100;
    public long rateLimitWindowMs = 1000; // 1 second
    public long blockDurationMs = 300_000; // 5 minutes

    public AntiDdosConfig() {}

    public AntiDdosConfig(int maxConnectionsPerIp, int maxPacketsPerSecond, long rateLimitWindowMs, long blockDurationMs) {
        this.maxConnectionsPerIp = maxConnectionsPerIp;
        this.maxPacketsPerSecond = maxPacketsPerSecond;
        this.rateLimitWindowMs = rateLimitWindowMs;
        this.blockDurationMs = blockDurationMs;
    }
}
