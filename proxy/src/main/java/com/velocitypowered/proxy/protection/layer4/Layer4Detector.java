/*
 * Copyright (C) 2018-2023 Velocity Contributors
 * Current Date and Time (UTC): 2025-06-14 08:38:15
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.layer4;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.netty.channel.ChannelHandlerContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.time.Duration;

public class Layer4Detector {
    private static final Logger logger = LogManager.getLogger(Layer4Detector.class);

    // Attack detection components
    private final SynFloodDetector synFloodDetector;
    private final UdpFloodDetector udpFloodDetector;
    private final ConnectionFloodDetector connectionFloodDetector;
    private final PortScanDetector portScanDetector;

    // Data tracking
    private final Map<InetAddress, ConnectionTracker> connectionTrackers;
    private final Cache<InetAddress, List<Integer>> portScanCache;

    // Configuration
    private final int synFloodThreshold;
    private final int udpFloodThreshold;
    private final int connectionFloodThreshold;
    private final int portScanThreshold;
    private final Duration trackingWindow;

    public Layer4Detector() {
        // Initialize detectors
        this.synFloodDetector = new SynFloodDetector();
        this.udpFloodDetector = new UdpFloodDetector();
        this.connectionFloodDetector = new ConnectionFloodDetector();
        this.portScanDetector = new PortScanDetector();

        // Initialize collections
        this.connectionTrackers = new ConcurrentHashMap<>();
        this.portScanCache = CacheBuilder.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .build();

        // Load configuration
        this.synFloodThreshold = 100; // SYN packets per second
        this.udpFloodThreshold = 1000; // UDP packets per second
        this.connectionFloodThreshold = 50; // Connections per second
        this.portScanThreshold = 20; // Unique ports per minute
        this.trackingWindow = Duration.ofSeconds(1);
    }

    public boolean analyze(ChannelHandlerContext ctx) {
        InetSocketAddress socketAddress = (InetSocketAddress) ctx.channel().remoteAddress();
        InetAddress address = socketAddress.getAddress();
        int port = socketAddress.getPort();

        try {
            // Track connection
            ConnectionTracker tracker = connectionTrackers.computeIfAbsent(address,
                k -> new ConnectionTracker());

            // Update connection stats
            tracker.recordConnection(port);

            // Check for SYN flood
            if (synFloodDetector.isFlooding(tracker)) {
                logger.warn("SYN flood detected from {}", address);
                return false;
            }

            // Check for UDP flood
            if (udpFloodDetector.isFlooding(tracker)) {
                logger.warn("UDP flood detected from {}", address);
                return false;
            }

            // Check for connection flood
            if (connectionFloodDetector.isFlooding(tracker)) {
                logger.warn("Connection flood detected from {}", address);
                return false;
            }

            // Check for port scan
            if (portScanDetector.isScanning(address, port)) {
                logger.warn("Port scan detected from {}", address);
                return false;
            }

            return true;

        } catch (Exception e) {
            logger.error("Error analyzing Layer 4 connection from " + address, e);
            return false;
        }
    }

    private static class ConnectionTracker {
        private final Queue<Long> connectionTimestamps;
        private final Queue<Long> synTimestamps;
        private final Queue<Long> udpTimestamps;
        private final Set<Integer> recentPorts;
        private final AtomicInteger activeConnections;

        public ConnectionTracker() {
            this.connectionTimestamps = new ConcurrentLinkedQueue<>();
            this.synTimestamps = new ConcurrentLinkedQueue<>();
            this.udpTimestamps = new ConcurrentLinkedQueue<>();
            this.recentPorts = Collections.newSetFromMap(new ConcurrentHashMap<>());
            this.activeConnections = new AtomicInteger();
        }

        public void recordConnection(int port) {
            long now = System.currentTimeMillis();
            connectionTimestamps.offer(now);
            recentPorts.add(port);
            activeConnections.incrementAndGet();

            // Clean old timestamps
            long cutoff = now - TimeUnit.MINUTES.toMillis(1);
            while (!connectionTimestamps.isEmpty() && connectionTimestamps.peek() < cutoff) {
                connectionTimestamps.poll();
            }
        }

        public void recordSyn() {
            synTimestamps.offer(System.currentTimeMillis());
        }

        public void recordUdp() {
            udpTimestamps.offer(System.currentTimeMillis());
        }

        public int getConnectionRate() {
            return connectionTimestamps.size();
        }

        public int getSynRate() {
            return synTimestamps.size();
        }

        public int getUdpRate() {
            return udpTimestamps.size();
        }

        public Set<Integer> getRecentPorts() {
            return recentPorts;
        }

        public int getActiveConnections() {
            return activeConnections.get();
        }
    }

    private class SynFloodDetector {
        public boolean isFlooding(ConnectionTracker tracker) {
            cleanOldTimestamps(tracker.synTimestamps);
            return tracker.getSynRate() > synFloodThreshold;
        }
    }

    private class UdpFloodDetector {
        public boolean isFlooding(ConnectionTracker tracker) {
            cleanOldTimestamps(tracker.udpTimestamps);
            return tracker.getUdpRate() > udpFloodThreshold;
        }
    }

    private class ConnectionFloodDetector {
        public boolean isFlooding(ConnectionTracker tracker) {
            cleanOldTimestamps(tracker.connectionTimestamps);
            return tracker.getConnectionRate() > connectionFloodThreshold;
        }
    }

    private class PortScanDetector {
        public boolean isScanning(InetAddress address, int port) {
            List<Integer> recentPorts = portScanCache.getIfPresent(address);
            if (recentPorts == null) {
                recentPorts = new ArrayList<>();
                portScanCache.put(address, recentPorts);
            }

            // Add new port
            recentPorts.add(port);

            // Check unique ports
            Set<Integer> uniquePorts = new HashSet<>(recentPorts);
            return uniquePorts.size() > portScanThreshold;
        }
    }

    private void cleanOldTimestamps(Queue<Long> timestamps) {
        long cutoff = System.currentTimeMillis() - trackingWindow.toMillis();
        while (!timestamps.isEmpty() && timestamps.peek() < cutoff) {
            timestamps.poll();
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats(InetAddress address) {
        ConnectionTracker tracker = connectionTrackers.get(address);
        if (tracker == null) {
            return Collections.emptyMap();
        }

        Map<String, Object> stats = new HashMap<>();
        stats.put("connection_rate", tracker.getConnectionRate());
        stats.put("syn_rate", tracker.getSynRate());
        stats.put("udp_rate", tracker.getUdpRate());
        stats.put("active_connections", tracker.getActiveConnections());
        stats.put("unique_ports", tracker.getRecentPorts().size());
        return stats;
    }
}