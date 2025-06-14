package com.velocitypowered.proxy.config;

import com.google.common.collect.ImmutableMap;
import java.util.List;
import java.util.Map;

public class ForcedHosts {
    private final Map<String, List<String>> forcedHosts;

    public ForcedHosts(Map<String, List<String>> forcedHosts) {
        this.forcedHosts = ImmutableMap.copyOf(forcedHosts);
    }

    public Map<String, List<String>> getForcedHosts() {
        return forcedHosts;
    }
}