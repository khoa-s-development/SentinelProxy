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
 * Current Date and Time (UTC): 2025-06-14 10:19:52
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.filter;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.velocitypowered.proxy.protocol.packet.PacketWrapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

public class FilterManager {
    private static final Logger logger = LogManager.getLogger(FilterManager.class);

    // Filter components
    private final PacketFilter packetFilter;
    private final ContentFilter contentFilter;
    private final RateFilter rateFilter;
    private final BehaviorFilter behaviorFilter;

    // Filter collections
    private final Map<String, Filter> activeFilters;
    private final Map<String, FilterChain> filterChains;
    private final Cache<InetAddress, FilterContext> filterContexts;
    private final Map<String, AtomicInteger> filterStats;

    // Configuration
    private final int maxFiltersPerChain;
    private final Duration contextExpiry;
    private final int maxContextSize;
    private final boolean strictMode;

    public FilterManager() {
        // Initialize components
        this.packetFilter = new PacketFilter();
        this.contentFilter = new ContentFilter();
        this.rateFilter = new RateFilter();
        this.behaviorFilter = new BehaviorFilter();

        // Initialize collections
        this.activeFilters = new ConcurrentHashMap<>();
        this.filterChains = new ConcurrentHashMap<>();
        this.filterContexts = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();
        this.filterStats = new ConcurrentHashMap<>();

        // Load configuration
        this.maxFiltersPerChain = 10;
        this.contextExpiry = Duration.ofHours(1);
        this.maxContextSize = 1000;
        this.strictMode = true;

        // Register default filters
        registerDefaultFilters();

        // Start maintenance tasks
        startMaintenanceTasks();
    }

    public boolean applyFilters(InetAddress address, PacketWrapper packet) {
        try {
            // Get or create filter context
            FilterContext context = getFilterContext(address);

            // Update context
            context.recordPacket(packet);

            // Apply each filter chain
            for (FilterChain chain : filterChains.values()) {
                if (!chain.apply(context, packet)) {
                    updateStats(chain.getName(), "blocked");
                    return false;
                }
                updateStats(chain.getName(), "passed");
            }

            return true;

        } catch (Exception e) {
            logger.error("Error applying filters for " + address, e);
            return strictMode ? false : true;
        }
    }

    private FilterContext getFilterContext(InetAddress address) {
        try {
            return filterContexts.get(address, () -> new FilterContext());
        } catch (ExecutionException e) {
            logger.error("Error getting filter context", e);
            return new FilterContext();
        }
    }

    public void registerFilter(String name, Filter filter) {
        activeFilters.put(name, filter);
        logger.info("Registered filter: {}", name);
    }

    public void createFilterChain(String name, List<String> filterNames) {
        if (filterNames.size() > maxFiltersPerChain) {
            throw new IllegalArgumentException("Too many filters in chain");
        }

        List<Filter> filters = new ArrayList<>();
        for (String filterName : filterNames) {
            Filter filter = activeFilters.get(filterName);
            if (filter == null) {
                throw new IllegalArgumentException("Unknown filter: " + filterName);
            }
            filters.add(filter);
        }

        FilterChain chain = new FilterChain(name, filters);
        filterChains.put(name, chain);
        logger.info("Created filter chain: {}", name);
    }

    private void registerDefaultFilters() {
        // Register packet filters
        registerFilter("packet.size", packetFilter.createSizeFilter());
        registerFilter("packet.rate", packetFilter.createRateFilter());
        registerFilter("packet.type", packetFilter.createTypeFilter());

        // Register content filters
        registerFilter("content.length", contentFilter.createLengthFilter());
        registerFilter("content.pattern", contentFilter.createPatternFilter());
        registerFilter("content.validation", contentFilter.createValidationFilter());

        // Register rate filters
        registerFilter("rate.connection", rateFilter.createConnectionFilter());
        registerFilter("rate.request", rateFilter.createRequestFilter());
        registerFilter("rate.bandwidth", rateFilter.createBandwidthFilter());

        // Register behavior filters
        registerFilter("behavior.sequence", behaviorFilter.createSequenceFilter());
        registerFilter("behavior.timing", behaviorFilter.createTimingFilter());
        registerFilter("behavior.pattern", behaviorFilter.createPatternFilter());
    }

    private void updateStats(String chainName, String result) {
        String key = chainName + "." + result;
        filterStats.computeIfAbsent(key, k -> new AtomicInteger())
                  .incrementAndGet();
    }

    private void startMaintenanceTasks() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactoryBuilder()
                .setNameFormat("filter-manager-%d")
                .setDaemon(true)
                .build()
        );

        // Clean up old contexts
        executor.scheduleAtFixedRate(() -> {
            try {
                filterContexts.cleanUp();
            } catch (Exception e) {
                logger.error("Error cleaning up filter contexts", e);
            }
        }, 1, 1, TimeUnit.HOURS);
    }

    private static class FilterChain {
        private final String name;
        private final List<Filter> filters;

        public FilterChain(String name, List<Filter> filters) {
            this.name = name;
            this.filters = new ArrayList<>(filters);
        }

        public boolean apply(FilterContext context, PacketWrapper packet) {
            for (Filter filter : filters) {
                if (!filter.test(context, packet)) {
                    return false;
                }
            }
            return true;
        }

        public String getName() {
            return name;
        }
    }

    private static class FilterContext {
        private final Queue<PacketWrapper> recentPackets;
        private final Map<String, Object> attributes;
        private volatile long lastUpdate;

        public FilterContext() {
            this.recentPackets = new ConcurrentLinkedQueue<>();
            this.attributes = new ConcurrentHashMap<>();
            this.lastUpdate = System.currentTimeMillis();
        }

        public void recordPacket(PacketWrapper packet) {
            recentPackets.offer(packet);
            while (recentPackets.size() > 1000) {
                recentPackets.poll();
            }
            lastUpdate = System.currentTimeMillis();
        }

        public List<PacketWrapper> getRecentPackets() {
            return new ArrayList<>(recentPackets);
        }

        public void setAttribute(String key, Object value) {
            attributes.put(key, value);
        }

        public Object getAttribute(String key) {
            return attributes.get(key);
        }

        public long getLastUpdate() {
            return lastUpdate;
        }
    }

    @FunctionalInterface
    private interface Filter {
        boolean test(FilterContext context, PacketWrapper packet);
    }

    private static class PacketFilter {
        public Filter createSizeFilter() {
            return (context, packet) -> packet.getSize() <= 1024 * 1024;
        }

        public Filter createRateFilter() {
            return (context, packet) -> {
                List<PacketWrapper> recent = context.getRecentPackets();
                return recent.size() <= 100;
            };
        }

        public Filter createTypeFilter() {
            return (context, packet) -> true; // Implement packet type validation
        }
    }

    private static class ContentFilter {
        public Filter createLengthFilter() {
            return (context, packet) -> true; // Implement content length validation
        }

        public Filter createPatternFilter() {
            return (context, packet) -> true; // Implement content pattern matching
        }

        public Filter createValidationFilter() {
            return (context, packet) -> true; // Implement content validation
        }
    }

    private static class RateFilter {
        public Filter createConnectionFilter() {
            return (context, packet) -> true; // Implement connection rate limiting
        }

        public Filter createRequestFilter() {
            return (context, packet) -> true; // Implement request rate limiting
        }

        public Filter createBandwidthFilter() {
            return (context, packet) -> true; // Implement bandwidth limiting
        }
    }

    private static class BehaviorFilter {
        public Filter createSequenceFilter() {
            return (context, packet) -> true; // Implement sequence validation
        }

        public Filter createTimingFilter() {
            return (context, packet) -> true; // Implement timing validation
        }

        public Filter createPatternFilter() {
            return (context, packet) -> true; // Implement pattern validation
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        
        Map<String, Integer> filterCounts = new HashMap<>();
        filterStats.forEach((key, count) -> 
            filterCounts.put(key, count.get()));
        stats.put("filter_counts", filterCounts);
        
        stats.put("active_contexts", filterContexts.size());
        stats.put("active_chains", filterChains.size());
        
        return stats;
    }

    public List<String> getActiveFilters() {
        return new ArrayList<>(activeFilters.keySet());
    }

    public List<String> getFilterChains() {
        return new ArrayList<>(filterChains.keySet());
    }
}