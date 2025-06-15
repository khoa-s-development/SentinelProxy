package com.velocitypowered.proxy.protection.config;
import java.util.Map;  // Thêm import này
import java.util.HashMap;  // Và import này nữa nếu bạn sử dụng HashMap

public class PacketFilter {
    private final boolean enabled;
    private final Map<String, Object> rateLimits;

    public PacketFilter(boolean enabled, Map<String, Object> rateLimits) {
        this.enabled = enabled;
        this.rateLimits = rateLimits;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public Map<String, Object> getRateLimits() {
        return rateLimits;
    }
}