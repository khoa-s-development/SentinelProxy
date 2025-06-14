/*
 * Copyright (C) 2018-2023 Velocity Contributors
 * Current Date and Time (UTC): 2025-06-14 08:39:38
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.layer7;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.netty.channel.ChannelHandlerContext;
import com.velocitypowered.proxy.protocol.packet.PacketWrapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public class Layer7Detector {
    private static final Logger logger = LogManager.getLogger(Layer7Detector.class);

    // Attack detection components
    private final HttpFloodDetector httpFloodDetector;
    private final SlowlorisDetector slowlorisDetector;
    private final PayloadAnalyzer payloadAnalyzer;
    private final BehaviorAnalyzer behaviorAnalyzer;

    // Data tracking
    private final Map<InetAddress, RequestTracker> requestTrackers;
    private final Cache<String, AtomicInteger> endpointStats;
    private final Set<Pattern> maliciousPatterns;

    // Configuration
    private final int httpFloodThreshold;
    private final int slowlorisThreshold;
    private final Duration requestTimeout;
    private final int maxPayloadSize;

    public Layer7Detector() {
        // Initialize detectors
        this.httpFloodDetector = new HttpFloodDetector();
        this.slowlorisDetector = new SlowlorisDetector();
        this.payloadAnalyzer = new PayloadAnalyzer();
        this.behaviorAnalyzer = new BehaviorAnalyzer();

        // Initialize collections
        this.requestTrackers = new ConcurrentHashMap<>();
        this.endpointStats = CacheBuilder.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .build();
        this.maliciousPatterns = new HashSet<>();

        // Load configuration
        this.httpFloodThreshold = 100; // requests per second
        this.slowlorisThreshold = 10; // seconds
        this.requestTimeout = Duration.ofSeconds(30);
        this.maxPayloadSize = 1024 * 1024; // 1MB

        // Initialize malicious patterns
        initializeMaliciousPatterns();
    }

    private void initializeMaliciousPatterns() {
        // SQL Injection patterns
        maliciousPatterns.add(Pattern.compile("(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*"));
        
        // XSS patterns
        maliciousPatterns.add(Pattern.compile("<script.*>.*</script.*>", Pattern.DOTALL));
        maliciousPatterns.add(Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE));
        
        // Path traversal
        maliciousPatterns.add(Pattern.compile("\\.\\./"));
        
        // Command injection
        maliciousPatterns.add(Pattern.compile("[;&|`]"));
    }

    public boolean analyze(ChannelHandlerContext ctx, PacketWrapper packet) {
        InetSocketAddress socketAddress = (InetSocketAddress) ctx.channel().remoteAddress();
        InetAddress address = socketAddress.getAddress();

        try {
            // Get or create request tracker
            RequestTracker tracker = requestTrackers.computeIfAbsent(address,
                k -> new RequestTracker());

            // Record request
            String endpoint = extractEndpoint(packet);
            tracker.recordRequest(endpoint, packet);

            // Check payload size
            if (packet.getSize() > maxPayloadSize) {
                logger.warn("Oversized payload from {}: {} bytes", address, packet.getSize());
                return false;
            }

            // HTTP flood detection
            if (httpFloodDetector.isFlooding(tracker)) {
                logger.warn("HTTP flood detected from {}", address);
                return false;
            }

            // Slowloris detection
            if (slowlorisDetector.isAttack(tracker)) {
                logger.warn("Slowloris attack detected from {}", address);
                return false;
            }

            // Payload analysis
            if (!payloadAnalyzer.analyze(packet, maliciousPatterns)) {
                logger.warn("Malicious payload detected from {}", address);
                return false;
            }

            // Behavior analysis
            if (!behaviorAnalyzer.analyze(tracker)) {
                logger.warn("Suspicious behavior detected from {}", address);
                return false;
            }

            return true;

        } catch (Exception e) {
            logger.error("Error analyzing Layer 7 packet from " + address, e);
            return false;
        }
    }

    private String extractEndpoint(PacketWrapper packet) {
        // Implementation to extract endpoint from packet
        return packet.getClass().getSimpleName();
    }

    private static class RequestTracker {
        private final Queue<RequestInfo> requests;
        private final Map<String, AtomicInteger> endpointCounts;
        private final Map<String, RequestInfo> incompleteRequests;
        private volatile long lastCompleteRequest;

        public RequestTracker() {
            this.requests = new ConcurrentLinkedQueue<>();
            this.endpointCounts = new ConcurrentHashMap<>();
            this.incompleteRequests = new ConcurrentHashMap<>();
            this.lastCompleteRequest = System.currentTimeMillis();
        }

        public void recordRequest(String endpoint, PacketWrapper packet) {
            long now = System.currentTimeMillis();
            RequestInfo info = new RequestInfo(endpoint, packet.getSize(), now);
            
            requests.offer(info);
            endpointCounts.computeIfAbsent(endpoint, k -> new AtomicInteger())
                         .incrementAndGet();

            if (isCompleteRequest(packet)) {
                lastCompleteRequest = now;
            } else {
                incompleteRequests.put(endpoint, info);
            }

            // Clean old requests
            cleanOldRequests(now);
        }

        private boolean isCompleteRequest(PacketWrapper packet) {
            // Implementation to check if request is complete
            return true;
        }

        private void cleanOldRequests(long now) {
            while (!requests.isEmpty() && now - requests.peek().timestamp > 60000) {
                RequestInfo old = requests.poll();
                AtomicInteger count = endpointCounts.get(old.endpoint);
                if (count != null && count.decrementAndGet() == 0) {
                    endpointCounts.remove(old.endpoint);
                }
            }
        }

        public int getRequestRate() {
            return requests.size();
        }

        public Map<String, Integer> getEndpointCounts() {
            Map<String, Integer> counts = new HashMap<>();
            endpointCounts.forEach((k, v) -> counts.put(k, v.get()));
            return counts;
        }

        public long getLastCompleteRequest() {
            return lastCompleteRequest;
        }

        public int getIncompleteRequestCount() {
            return incompleteRequests.size();
        }
    }

    private static class RequestInfo {
        final String endpoint;
        final int size;
        final long timestamp;

        RequestInfo(String endpoint, int size, long timestamp) {
            this.endpoint = endpoint;
            this.size = size;
            this.timestamp = timestamp;
        }
    }

    private class HttpFloodDetector {
        public boolean isFlooding(RequestTracker tracker) {
            return tracker.getRequestRate() > httpFloodThreshold;
        }
    }

    private class SlowlorisDetector {
        public boolean isAttack(RequestTracker tracker) {
            long timeSinceComplete = System.currentTimeMillis() - tracker.getLastCompleteRequest();
            return timeSinceComplete > slowlorisThreshold * 1000 && 
                   tracker.getIncompleteRequestCount() > 0;
        }
    }

    private class PayloadAnalyzer {
        public boolean analyze(PacketWrapper packet, Set<Pattern> patterns) {
            String payload = extractPayload(packet);
            if (payload == null) return true;

            // Check for malicious patterns
            for (Pattern pattern : patterns) {
                if (pattern.matcher(payload).find()) {
                    return false;
                }
            }

            return true;
        }

        private String extractPayload(PacketWrapper packet) {
            // Implementation to extract payload from packet
            return null;
        }
    }

    private class BehaviorAnalyzer {
        public boolean analyze(RequestTracker tracker) {
            // Check for suspicious patterns in endpoint access
            Map<String, Integer> counts = tracker.getEndpointCounts();
            
            // Check for endpoint abuse
            for (Map.Entry<String, Integer> entry : counts.entrySet()) {
                if (entry.getValue() > httpFloodThreshold) {
                    return false;
                }
            }

            // Check for request distribution
            if (isAnomalousDistribution(counts)) {
                return false;
            }

            return true;
        }

        private boolean isAnomalousDistribution(Map<String, Integer> counts) {
            // Implementation to check for anomalous request distribution
            return false;
        }
    }

    // Stats and monitoring
    public Map<String, Object> getStats(InetAddress address) {
        RequestTracker tracker = requestTrackers.get(address);
        if (tracker == null) {
            return Collections.emptyMap();
        }

        Map<String, Object> stats = new HashMap<>();
        stats.put("request_rate", tracker.getRequestRate());
        stats.put("endpoint_counts", tracker.getEndpointCounts());
        stats.put("incomplete_requests", tracker.getIncompleteRequestCount());
        stats.put("last_complete_request", tracker.getLastCompleteRequest());
        return stats;
    }
}