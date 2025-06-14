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
 * Current Date and Time (UTC): 2025-06-14 08:41:18
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.packet;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.netty.channel.ChannelHandlerContext;
import com.velocitypowered.proxy.protocol.packet.PacketWrapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class PacketAnalyzer {
    private static final Logger logger = LogManager.getLogger(PacketAnalyzer.class);

    // Analysis components
    private final PacketValidator packetValidator;
    private final ContentAnalyzer contentAnalyzer;
    private final SequenceAnalyzer sequenceAnalyzer;
    private final TimingAnalyzer timingAnalyzer;

    // Data tracking
    private final Map<InetAddress, PacketHistory> packetHistories;
    private final Cache<String, PacketStats> packetStats;

    // Configuration
    private final int maxPacketSize;
    private final int sequenceThreshold;
    private final long timingThreshold;
    private final Duration historyWindow;

    public PacketAnalyzer() {
        // Initialize analyzers
        this.packetValidator = new PacketValidator();
        this.contentAnalyzer = new ContentAnalyzer();
        this.sequenceAnalyzer = new SequenceAnalyzer();
        this.timingAnalyzer = new TimingAnalyzer();

        // Initialize collections
        this.packetHistories = new ConcurrentHashMap<>();
        this.packetStats = CacheBuilder.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .build();

        // Load configuration
        this.maxPacketSize = 32 * 1024; // 32KB
        this.sequenceThreshold = 100; // packets
        this.timingThreshold = 50; // milliseconds
        this.historyWindow = Duration.ofMinutes(1);
    }

    public boolean analyzePacket(PacketWrapper packet, ChannelHandlerContext ctx) {
        InetSocketAddress socketAddress = (InetSocketAddress) ctx.channel().remoteAddress();
        InetAddress address = socketAddress.getAddress();

        try {
            // Get or create packet history
            PacketHistory history = packetHistories.computeIfAbsent(address,
                k -> new PacketHistory());

            // Basic validation
            if (!packetValidator.validate(packet)) {
                logger.warn("Invalid packet from {}: {}", address, packet.getClass().getSimpleName());
                return false;
            }

            // Content analysis
            if (!contentAnalyzer.analyze(packet)) {
                logger.warn("Malicious content detected from {}", address);
                return false;
            }

            // Record packet
            history.recordPacket(packet);

            // Sequence analysis
            if (!sequenceAnalyzer.analyze(history)) {
                logger.warn("Suspicious packet sequence from {}", address);
                return false;
            }

            // Timing analysis
            if (!timingAnalyzer.analyze(history)) {
                logger.warn("Suspicious packet timing from {}", address);
                return false;
            }

            // Update statistics
            updateStats(address, packet);

            return true;

        } catch (Exception e) {
            logger.error("Error analyzing packet from " + address, e);
            return false;
        }
    }

    private void updateStats(InetAddress address, PacketWrapper packet) {
        String key = address.getHostAddress() + ":" + packet.getClass().getSimpleName();
        PacketStats stats = packetStats.getIfPresent(key);
        if (stats == null) {
            stats = new PacketStats();
            packetStats.put(key, stats);
        }
        stats.recordPacket(packet);
    }

    private static class PacketHistory {
        private final Queue<PacketInfo> packets;
        private final Map<Class<?>, Queue<Long>> timingMap;
        private final AtomicInteger sequenceCount;

        public PacketHistory() {
            this.packets = new ConcurrentLinkedQueue<>();
            this.timingMap = new ConcurrentHashMap<>();
            this.sequenceCount = new AtomicInteger();
        }

        public void recordPacket(PacketWrapper packet) {
            long now = System.currentTimeMillis();
            PacketInfo info = new PacketInfo(packet, now);
            packets.offer(info);
            
            // Record timing
            Queue<Long> timings = timingMap.computeIfAbsent(packet.getClass(),
                k -> new ConcurrentLinkedQueue<>());
            timings.offer(now);

            // Clean old records
            cleanOldRecords(now);
        }

        private void cleanOldRecords(long now) {
            // Clean packet history
            while (!packets.isEmpty() && now - packets.peek().timestamp > 60000) {
                packets.poll();
            }

            // Clean timing records
            for (Queue<Long> timings : timingMap.values()) {
                while (!timings.isEmpty() && now - timings.peek() > 60000) {
                    timings.poll();
                }
            }
        }

        public Queue<PacketInfo> getRecentPackets() {
            return packets;
        }

        public Map<Class<?>, Queue<Long>> getTimingMap() {
            return timingMap;
        }
    }

    private static class PacketInfo {
        final PacketWrapper packet;
        final long timestamp;

        PacketInfo(PacketWrapper packet, long timestamp) {
            this.packet = packet;
            this.timestamp = timestamp;
        }
    }

    private static class PacketStats {
        private final AtomicInteger count;
        private final AtomicInteger totalSize;
        private volatile long lastUpdate;

        public PacketStats() {
            this.count = new AtomicInteger();
            this.totalSize = new AtomicInteger();
            this.lastUpdate = System.currentTimeMillis();
        }

        public void recordPacket(PacketWrapper packet) {
            count.incrementAndGet();
            totalSize.addAndGet(packet.getSize());
            lastUpdate = System.currentTimeMillis();
        }
    }

    private class PacketValidator {
        public boolean validate(PacketWrapper packet) {
            // Check packet size
            if (packet.getSize() > maxPacketSize) {
                return false;
            }

            // Validate packet structure
            if (!isValidStructure(packet)) {
                return false;
            }

            return true;
        }

        private boolean isValidStructure(PacketWrapper packet) {
            try {
                // Implementation to validate packet structure
                return true;
            } catch (Exception e) {
                return false;
            }
        }
    }

    private class ContentAnalyzer {
        public boolean analyze(PacketWrapper packet) {
            // Check for malicious content
            if (containsMaliciousContent(packet)) {
                return false;
            }

            // Validate packet data
            if (!isValidContent(packet)) {
                return false;
            }

            return true;
        }

        private boolean containsMaliciousContent(PacketWrapper packet) {
            // Implementation to detect malicious content
            return false;
        }

        private boolean isValidContent(PacketWrapper packet) {
            // Implementation to validate packet content
            return true;
        }
    }

    private class SequenceAnalyzer {
        public boolean analyze(PacketHistory history) {
            Queue<PacketInfo> packets = history.getRecentPackets();
            
            // Check sequence length
            if (packets.size() > sequenceThreshold) {
                return false;
            }

            // Check for suspicious patterns
            if (hasAnomalousPattern(packets)) {
                return false;
            }

            return true;
        }

        private boolean hasAnomalousPattern(Queue<PacketInfo> packets) {
            // Implementation to detect anomalous patterns
            return false;
        }
    }

    private class TimingAnalyzer {
        public boolean analyze(PacketHistory history) {
            Map<Class<?>, Queue<Long>> timingMap = history.getTimingMap();

            // Check timing patterns for each packet type
            for (Map.Entry<Class<?>, Queue<Long>> entry : timingMap.entrySet()) {
                if (hasAnomalousTiming(entry.getValue())) {
                    return false;
                }
            }

            return true;
        }

        private boolean hasAnomalousTiming(Queue<Long> timings) {
            if (timings.size() < 2) {
                return false;
            }

            // Check for too rapid sequences
            Long[] timestamps = timings.toArray(new Long[0]);
            for (int i = 1; i < timestamps.length; i++) {
                if (timestamps[i] - timestamps[i-1] < timingThreshold) {
                    return true;
                }
            }

            return false;
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats(InetAddress address) {
        PacketHistory history = packetHistories.get(address);
        if (history == null) {
            return Collections.emptyMap();
        }

        Map<String, Object> stats = new HashMap<>();
        stats.put("recent_packets", history.getRecentPackets().size());
        
        Map<String, Integer> packetTypeCount = new HashMap<>();
        history.getTimingMap().forEach((type, timings) -> 
            packetTypeCount.put(type.getSimpleName(), timings.size()));
        stats.put("packet_types", packetTypeCount);
        
        return stats;
    }
}