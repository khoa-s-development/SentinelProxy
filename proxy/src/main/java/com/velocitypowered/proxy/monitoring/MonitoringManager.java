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
 * Current Date and Time (UTC): 2025-06-21 12:05:58
 * Current User's Login: akk1to
 */

package com.velocitypowered.proxy.monitoring;

import com.velocitypowered.api.proxy.ProxyServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.RuntimeMXBean;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class MonitoringManager {
    private static final Logger logger = LoggerFactory.getLogger(MonitoringManager.class);
    
    private final ProxyServer server;
    private final ScheduledExecutorService scheduler;
    private final MemoryMXBean memoryBean;
    private final RuntimeMXBean runtimeBean;
    
    // Metrics
    private final AtomicLong totalConnections = new AtomicLong(0);
    private final AtomicLong totalPackets = new AtomicLong(0);
    private final AtomicLong blockedConnections = new AtomicLong(0);
    private final AtomicLong startTime;
    
    private boolean running = false;
    private boolean enabled = true;

    public MonitoringManager(ProxyServer server) {
        this.server = server;
        this.scheduler = Executors.newScheduledThreadPool(2);
        this.memoryBean = ManagementFactory.getMemoryMXBean();
        this.runtimeBean = ManagementFactory.getRuntimeMXBean();
        this.startTime = new AtomicLong(System.currentTimeMillis());
    }

    public void initialize() {
        logger.info("Initializing monitoring manager...");
        if (enabled) {
            start();
        }
        logger.info("Monitoring manager initialized");
    }

    public void start() {
        if (running) {
            return;
        }
        
        running = true;
        
        // Schedule periodic monitoring tasks
        scheduler.scheduleWithFixedDelay(this::collectMetrics, 30, 30, TimeUnit.SECONDS);
        scheduler.scheduleWithFixedDelay(this::logSystemStats, 5, 5, TimeUnit.MINUTES);
        
        logger.info("Monitoring manager started");
    }

    public void stop() {
        if (!running) {
            return;
        }
        
        running = false;
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        logger.info("Monitoring manager stopped");
    }

    public void cleanup() {
        stop();
        totalConnections.set(0);
        totalPackets.set(0);
        blockedConnections.set(0);
    }

    private void collectMetrics() {
        try {
            // Collect and store metrics here
            long currentMemory = memoryBean.getHeapMemoryUsage().getUsed();
            long maxMemory = memoryBean.getHeapMemoryUsage().getMax();
            long uptime = runtimeBean.getUptime();
            
            // Log debug metrics
            logger.debug("Memory Usage: {} MB / {} MB", 
                currentMemory / 1024 / 1024, maxMemory / 1024 / 1024);
            logger.debug("Uptime: {} minutes", uptime / 1000 / 60);
            logger.debug("Connected Players: {}", server.getPlayerCount());
            logger.debug("Total Connections: {}", totalConnections.get());
            logger.debug("Blocked Connections: {}", blockedConnections.get());
            
        } catch (Exception e) {
            logger.error("Error collecting metrics", e);
        }
    }

    private void logSystemStats() {
        try {
            long usedMemory = memoryBean.getHeapMemoryUsage().getUsed() / 1024 / 1024;
            long maxMemory = memoryBean.getHeapMemoryUsage().getMax() / 1024 / 1024;
            long uptime = runtimeBean.getUptime() / 1000 / 60; // minutes
            
            logger.info("System Stats - Memory: {}MB/{}MB, Uptime: {}min, Players: {}, Connections: {}", 
                usedMemory, maxMemory, uptime, server.getPlayerCount(), totalConnections.get());
        } catch (Exception e) {
            logger.error("Error logging system stats", e);
        }
    }

    // Metric tracking methods
    public void incrementTotalConnections() {
        totalConnections.incrementAndGet();
    }

    public void incrementTotalPackets() {
        totalPackets.incrementAndGet();
    }

    public void incrementBlockedConnections() {
        blockedConnections.incrementAndGet();
    }

    public void addPackets(long count) {
        totalPackets.addAndGet(count);
    }

    // Getters
    public long getTotalConnections() {
        return totalConnections.get();
    }

    public long getTotalPackets() {
        return totalPackets.get();
    }

    public long getBlockedConnections() {
        return blockedConnections.get();
    }

    public long getUptime() {
        return System.currentTimeMillis() - startTime.get();
    }

    public boolean isRunning() {
        return running;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        if (enabled && !running) {
            start();
        } else if (!enabled && running) {
            stop();
        }
    }

    // System information getters
    public double getMemoryUsagePercent() {
        long used = memoryBean.getHeapMemoryUsage().getUsed();
        long max = memoryBean.getHeapMemoryUsage().getMax();
        return max > 0 ? (double) used / max * 100 : 0;
    }

    public long getUsedMemoryMB() {
        return memoryBean.getHeapMemoryUsage().getUsed() / 1024 / 1024;
    }

    public long getMaxMemoryMB() {
        return memoryBean.getHeapMemoryUsage().getMax() / 1024 / 1024;
    }

    public long getUptimeMinutes() {
        return runtimeBean.getUptime() / 1000 / 60;
    }
}