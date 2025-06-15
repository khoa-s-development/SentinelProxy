package com.velocitypowered.proxy.config;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableList;
import java.util.List;
import java.util.Map;

public class Servers {
    private final Map<String, String> servers;
    private final List<String> attemptConnectionOrder;

    public Servers(Map<String, String> servers, List<String> attemptConnectionOrder) {
        this.servers = ImmutableMap.copyOf(servers);
        this.attemptConnectionOrder = ImmutableList.copyOf(attemptConnectionOrder);
    }

    public Map<String, String> getServers() {
        return servers;
    }

    public List<String> getAttemptConnectionOrder() {
        return attemptConnectionOrder;
    }
}