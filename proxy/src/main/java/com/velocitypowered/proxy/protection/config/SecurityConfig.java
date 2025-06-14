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
 * Current Date and Time (UTC): 2025-06-14 10:32:57
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.config;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

public class SecurityConfig {
    private static final Logger logger = LogManager.getLogger(SecurityConfig.class);

    // Configuration sections
    private final RateLimitConfig rateLimitConfig;
    private final FilterConfig filterConfig;
    private final BlacklistConfig blacklistConfig;
    private final WhitelistConfig whitelistConfig;
    private final RuleConfig ruleConfig;
    private final LoggingConfig loggingConfig;

    // Runtime configuration
    private final Map<String, Object> runtimeConfig;
    private final AtomicReference<ConfigState> currentState;
    private final Path configPath;
    private volatile boolean isDirty;

    public SecurityConfig(Path configPath) {
        // Initialize configuration sections
        this.rateLimitConfig = new RateLimitConfig();
        this.filterConfig = new FilterConfig();
        this.blacklistConfig = new BlacklistConfig();
        this.whitelistConfig = new WhitelistConfig();
        this.ruleConfig = new RuleConfig();
        this.loggingConfig = new LoggingConfig();

        // Initialize runtime configuration
        this.runtimeConfig = new ConcurrentHashMap<>();
        this.currentState = new AtomicReference<>(new ConfigState());
        this.configPath = configPath;
        this.isDirty = false;

        // Load configuration
        loadConfig();

        // Start auto-save task
        startAutoSave();
    }

    public void loadConfig() {
        try {
            if (!Files.exists(configPath)) {
                saveDefaultConfig();
            }

            Properties props = new Properties();
            try (Reader reader = Files.newBufferedReader(configPath)) {
                props.load(reader);
            }

            // Load each section
            rateLimitConfig.load(props);
            filterConfig.load(props);
            blacklistConfig.load(props);
            whitelistConfig.load(props);
            ruleConfig.load(props);
            loggingConfig.load(props);

            // Update current state
            updateState();

            logger.info("Loaded security configuration from {}", configPath);
        } catch (Exception e) {
            logger.error("Error loading security configuration", e);
        }
    }

    public void saveConfig() {
        try {
            Properties props = new Properties();

            // Save each section
            rateLimitConfig.save(props);
            filterConfig.save(props);
            blacklistConfig.save(props);
            whitelistConfig.save(props);
            ruleConfig.save(props);
            loggingConfig.save(props);

            try (Writer writer = Files.newBufferedWriter(configPath)) {
                props.store(writer, "Velocity Security Configuration");
            }

            isDirty = false;
            logger.info("Saved security configuration to {}", configPath);
        } catch (Exception e) {
            logger.error("Error saving security configuration", e);
        }
    }

    private void saveDefaultConfig() {
        try {
            Files.createDirectories(configPath.getParent());
            
            Properties props = new Properties();
            setDefaultProperties(props);

            try (Writer writer = Files.newBufferedWriter(configPath)) {
                props.store(writer, "Default Velocity Security Configuration");
            }

            logger.info("Created default security configuration at {}", configPath);
        } catch (Exception e) {
            logger.error("Error creating default configuration", e);
        }
    }

    private void setDefaultProperties(Properties props) {
        // Rate limiting defaults
        props.setProperty("rate.connection.max", "100");
        props.setProperty("rate.packet.max", "1000");
        props.setProperty("rate.bandwidth.max", "1048576");

        // Filter defaults
        props.setProperty("filter.enabled", "true");
        props.setProperty("filter.strict", "true");
        props.setProperty("filter.max-chain-size", "10");

        // Blacklist defaults
        props.setProperty("blacklist.enabled", "true");
        props.setProperty("blacklist.max-entries", "1000");
        props.setProperty("blacklist.expiry", "24h");

        // Whitelist defaults
        props.setProperty("whitelist.enabled", "false");
        props.setProperty("whitelist.max-entries", "1000");
        props.setProperty("whitelist.expiry", "720h");

        // Rule defaults
        props.setProperty("rules.enabled", "true");
        props.setProperty("rules.max-per-set", "50");
        props.setProperty("rules.strict", "true");

        // Logging defaults
        props.setProperty("logging.enabled", "true");
        props.setProperty("logging.level", "INFO");
        props.setProperty("logging.file", "security.log");
    }

    private void updateState() {
        ConfigState newState = new ConfigState();
        
        // Update state from each section
        newState.rateLimit.putAll(rateLimitConfig.getState());
        newState.filters.putAll(filterConfig.getState());
        newState.blacklist.putAll(blacklistConfig.getState());
        newState.whitelist.putAll(whitelistConfig.getState());
        newState.rules.putAll(ruleConfig.getState());
        newState.logging.putAll(loggingConfig.getState());

        currentState.set(newState);
    }

    private void startAutoSave() {
        Thread autoSaveThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(Duration.ofMinutes(5).toMillis());
                    if (isDirty) {
                        saveConfig();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }, "security-config-autosave");
        
        autoSaveThread.setDaemon(true);
        autoSaveThread.start();
    }

    // Configuration section classes
    private static class RateLimitConfig {
        private final Map<String, Integer> limits = new HashMap<>();

        public void load(Properties props) {
            limits.put("connection", Integer.parseInt(props.getProperty("rate.connection.max", "100")));
            limits.put("packet", Integer.parseInt(props.getProperty("rate.packet.max", "1000")));
            limits.put("bandwidth", Integer.parseInt(props.getProperty("rate.bandwidth.max", "1048576")));
        }

        public void save(Properties props) {
            props.setProperty("rate.connection.max", String.valueOf(limits.get("connection")));
            props.setProperty("rate.packet.max", String.valueOf(limits.get("packet")));
            props.setProperty("rate.bandwidth.max", String.valueOf(limits.get("bandwidth")));
        }

        public Map<String, Object> getState() {
            return new HashMap<>(limits);
        }
    }

    private static class FilterConfig {
        private boolean enabled;
        private boolean strict;
        private int maxChainSize;

        public void load(Properties props) {
            enabled = Boolean.parseBoolean(props.getProperty("filter.enabled", "true"));
            strict = Boolean.parseBoolean(props.getProperty("filter.strict", "true"));
            maxChainSize = Integer.parseInt(props.getProperty("filter.max-chain-size", "10"));
        }

        public void save(Properties props) {
            props.setProperty("filter.enabled", String.valueOf(enabled));
            props.setProperty("filter.strict", String.valueOf(strict));
            props.setProperty("filter.max-chain-size", String.valueOf(maxChainSize));
        }

        public Map<String, Object> getState() {
            Map<String, Object> state = new HashMap<>();
            state.put("enabled", enabled);
            state.put("strict", strict);
            state.put("maxChainSize", maxChainSize);
            return state;
        }
    }

    private static class BlacklistConfig {
        private boolean enabled;
        private int maxEntries;
        private Duration expiry;

        public void load(Properties props) {
            enabled = Boolean.parseBoolean(props.getProperty("blacklist.enabled", "true"));
            maxEntries = Integer.parseInt(props.getProperty("blacklist.max-entries", "1000"));
            expiry = Duration.parse("PT" + props.getProperty("blacklist.expiry", "24h"));
        }

        public void save(Properties props) {
            props.setProperty("blacklist.enabled", String.valueOf(enabled));
            props.setProperty("blacklist.max-entries", String.valueOf(maxEntries));
            props.setProperty("blacklist.expiry", expiry.toString().substring(2));
        }

        public Map<String, Object> getState() {
            Map<String, Object> state = new HashMap<>();
            state.put("enabled", enabled);
            state.put("maxEntries", maxEntries);
            state.put("expiry", expiry);
            return state;
        }
    }

    private static class WhitelistConfig {
        private boolean enabled;
        private int maxEntries;
        private Duration expiry;

        public void load(Properties props) {
            enabled = Boolean.parseBoolean(props.getProperty("whitelist.enabled", "false"));
            maxEntries = Integer.parseInt(props.getProperty("whitelist.max-entries", "1000"));
            expiry = Duration.parse("PT" + props.getProperty("whitelist.expiry", "720h"));
        }

        public void save(Properties props) {
            props.setProperty("whitelist.enabled", String.valueOf(enabled));
            props.setProperty("whitelist.max-entries", String.valueOf(maxEntries));
            props.setProperty("whitelist.expiry", expiry.toString().substring(2));
        }

        public Map<String, Object> getState() {
            Map<String, Object> state = new HashMap<>();
            state.put("enabled", enabled);
            state.put("maxEntries", maxEntries);
            state.put("expiry", expiry);
            return state;
        }
    }

    private static class RuleConfig {
        private boolean enabled;
        private int maxPerSet;
        private boolean strict;

        public void load(Properties props) {
            enabled = Boolean.parseBoolean(props.getProperty("rules.enabled", "true"));
            maxPerSet = Integer.parseInt(props.getProperty("rules.max-per-set", "50"));
            strict = Boolean.parseBoolean(props.getProperty("rules.strict", "true"));
        }

        public void save(Properties props) {
            props.setProperty("rules.enabled", String.valueOf(enabled));
            props.setProperty("rules.max-per-set", String.valueOf(maxPerSet));
            props.setProperty("rules.strict", String.valueOf(strict));
        }

        public Map<String, Object> getState() {
            Map<String, Object> state = new HashMap<>();
            state.put("enabled", enabled);
            state.put("maxPerSet", maxPerSet);
            state.put("strict", strict);
            return state;
        }
    }

    private static class LoggingConfig {
        private boolean enabled;
        private String level;
        private String file;

        public void load(Properties props) {
            enabled = Boolean.parseBoolean(props.getProperty("logging.enabled", "true"));
            level = props.getProperty("logging.level", "INFO");
            file = props.getProperty("logging.file", "security.log");
        }

        public void save(Properties props) {
            props.setProperty("logging.enabled", String.valueOf(enabled));
            props.setProperty("logging.level", level);
            props.setProperty("logging.file", file);
        }

        public Map<String, Object> getState() {
            Map<String, Object> state = new HashMap<>();
            state.put("enabled", enabled);
            state.put("level", level);
            state.put("file", file);
            return state;
        }
    }

    private static class ConfigState {
        private final Map<String, Object> rateLimit = new HashMap<>();
        private final Map<String, Object> filters = new HashMap<>();
        private final Map<String, Object> blacklist = new HashMap<>();
        private final Map<String, Object> whitelist = new HashMap<>();
        private final Map<String, Object> rules = new HashMap<>();
        private final Map<String, Object> logging = new HashMap<>();
    }

    // Public API
    public Map<String, Object> getConfig(String section) {
        ConfigState state = currentState.get();
        switch (section) {
            case "rateLimit": return ImmutableMap.copyOf(state.rateLimit);
            case "filters": return ImmutableMap.copyOf(state.filters);
            case "blacklist": return ImmutableMap.copyOf(state.blacklist);
            case "whitelist": return ImmutableMap.copyOf(state.whitelist);
            case "rules": return ImmutableMap.copyOf(state.rules);
            case "logging": return ImmutableMap.copyOf(state.logging);
            default: throw new IllegalArgumentException("Unknown config section: " + section);
        }
    }

    public void updateConfig(String section, String key, Object value) {
        switch (section) {
            case "rateLimit":
                if (value instanceof Integer) {
                    rateLimitConfig.limits.put(key, (Integer) value);
                }
                break;
            case "filters":
                updateFilterConfig(key, value);
                break;
            case "blacklist":
                updateBlacklistConfig(key, value);
                break;
            case "whitelist":
                updateWhitelistConfig(key, value);
                break;
            case "rules":
                updateRuleConfig(key, value);
                break;
            case "logging":
                updateLoggingConfig(key, value);
                break;
            default:
                throw new IllegalArgumentException("Unknown config section: " + section);
        }

        isDirty = true;
        updateState();
    }

    private void updateFilterConfig(String key, Object value) {
        switch (key) {
            case "enabled":
                if (value instanceof Boolean) {
                    filterConfig.enabled = (Boolean) value;
                }
                break;
            case "strict":
                if (value instanceof Boolean) {
                    filterConfig.strict = (Boolean) value;
                }
                break;
            case "maxChainSize":
                if (value instanceof Integer) {
                    filterConfig.maxChainSize = (Integer) value;
                }
                break;
        }
    }

    private void updateBlacklistConfig(String key, Object value) {
        switch (key) {
            case "enabled":
                if (value instanceof Boolean) {
                    blacklistConfig.enabled = (Boolean) value;
                }
                break;
            case "maxEntries":
                if (value instanceof Integer) {
                    blacklistConfig.maxEntries = (Integer) value;
                }
                break;
            case "expiry":
                if (value instanceof String) {
                    blacklistConfig.expiry = Duration.parse("PT" + value);
                }
                break;
        }
    }

    private void updateWhitelistConfig(String key, Object value) {
        switch (key) {
            case "enabled":
                if (value instanceof Boolean) {
                    whitelistConfig.enabled = (Boolean) value;
                }
                break;
            case "maxEntries":
                if (value instanceof Integer) {
                    whitelistConfig.maxEntries = (Integer) value;
                }
                break;
            case "expiry":
                if (value instanceof String) {
                    whitelistConfig.expiry = Duration.parse("PT" + value);
                }
                break;
        }
    }

    private void updateRuleConfig(String key, Object value) {
        switch (key) {
            case "enabled":
                if (value instanceof Boolean) {
                    ruleConfig.enabled = (Boolean) value;
                }
                break;
            case "maxPerSet":
                if (value instanceof Integer) {
                    ruleConfig.maxPerSet = (Integer) value;
                }
                break;
            case "strict":
                if (value instanceof Boolean) {
                    ruleConfig.strict = (Boolean) value;
                }
                break;
        }
    }

    private void updateLoggingConfig(String key, Object value) {
        switch (key) {
            case "enabled":
                if (value instanceof Boolean) {
                    loggingConfig.enabled = (Boolean) value;
                }
                break;
            case "level":
                if (value instanceof String) {
                    loggingConfig.level = (String) value;
                }
                break;
            case "file":
                if (value instanceof String) {
                    loggingConfig.file = (String) value;
                }
                break;
        }
    }

    public List<String> getConfigSections() {
        return ImmutableList.of("rateLimit", "filters", "blacklist", 
                               "whitelist", "rules", "logging");
    }

    public void reload() {
        loadConfig();
    }
}