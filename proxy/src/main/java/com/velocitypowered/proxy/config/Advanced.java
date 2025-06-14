package com.velocitypowered.proxy.config;

public class Advanced {
    private final int compressionLevel;
    private final int compressionThreshold;
    private final int loginTimeout;
    private final int connectionTimeout;
    private final int readTimeout;

    public Advanced(int compressionLevel, int compressionThreshold,
                   int loginTimeout, int connectionTimeout, int readTimeout) {
        this.compressionLevel = compressionLevel;
        this.compressionThreshold = compressionThreshold;
        this.loginTimeout = loginTimeout;
        this.connectionTimeout = connectionTimeout;
        this.readTimeout = readTimeout;
    }

    public int getCompressionLevel() {
        return compressionLevel;
    }

    public int getCompressionThreshold() {
        return compressionThreshold;
    }

    public int getLoginTimeout() {
        return loginTimeout;
    }

    public int getConnectionTimeout() {
        return connectionTimeout;
    }

    public int getReadTimeout() {
        return readTimeout;
    }
}