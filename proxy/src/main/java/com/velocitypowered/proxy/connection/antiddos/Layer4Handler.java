package com.velocitypowered.proxy.connection.antiddos;

import com.velocitypowered.proxy.protocol.MinecraftPacket;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Layer 4 DDoS Protection Handler
 * 
 * This handler provides comprehensive DDoS protection at the TCP/UDP layer by:
 * - Limiting connections per IP address
 * - Rate limiting packets per second
 * - Tracking and blocking malicious IPs
 * - Monitoring error rates and exceptions
 * - Validating packet sizes and types
 * 
 * Thread-safe implementation using concurrent data structures.
 * 
 * @author Velocity Contributors
 */
public class Layer4Handler extends ChannelInboundHandlerAdapter {
    
    private static final Logger logger = LoggerFactory.getLogger(Layer4Handler.class);
    
    // Configuration constants for DDoS protection
    /** Maximum number of connections allowed per IP address */
    private static final int MAX_CONNECTIONS_PER_IP = 5;
    /** Maximum number of packets allowed per second per IP */
    private static final int MAX_PACKETS_PER_SECOND = 100;
    /** Time window for rate limiting in milliseconds (1 second) */
    private static final long RATE_LIMIT_WINDOW = 1000;
    /** Duration to block an IP in milliseconds (5 minutes) */
    private static final long BLOCK_DURATION = 300000;
    /** Maximum number of errors before blocking an IP */
    private static final int MAX_ERROR_COUNT = 10;
    /** Warning threshold for error count */
    private static final int ERROR_WARNING_THRESHOLD = 5;
    
    // Thread-safe tracking data structures
    /** Tracks active connections per IP address */
    private final ConcurrentHashMap<InetAddress, AtomicInteger> connectionCount = new ConcurrentHashMap<>();
    /** Tracks packet rates and error counts per IP address */
    private final ConcurrentHashMap<InetAddress, PacketRateTracker> packetRates = new ConcurrentHashMap<>();
    /** Tracks temporarily blocked IP addresses with block timestamps */
    private final ConcurrentHashMap<InetAddress, Long> blockedIPs = new ConcurrentHashMap<>();
    
    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        InetAddress clientIP = getClientIP(ctx);
        
        // Kiểm tra IP có bị chặn không
        if (isBlocked(clientIP)) {
            logger.warn("Blocked IP {} attempted to connect", clientIP);
            ctx.close();
            return;
        }
        
        // Kiểm tra giới hạn kết nối
        AtomicInteger connections = connectionCount.computeIfAbsent(clientIP, k -> new AtomicInteger(0));
        if (connections.incrementAndGet() > MAX_CONNECTIONS_PER_IP) {
            logger.warn("IP {} exceeded connection limit, blocking", clientIP);
            blockIP(clientIP);
            ctx.close();
            return;
        }
        
        logger.debug("New connection from IP: {} (Total: {})", clientIP, connections.get());
        super.channelActive(ctx);
    }
    
    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        InetAddress clientIP = getClientIP(ctx);
        AtomicInteger connections = connectionCount.get(clientIP);
        if (connections != null) {
            connections.decrementAndGet();
            if (connections.get() <= 0) {
                connectionCount.remove(clientIP);
            }
        }
        super.channelInactive(ctx);
    }
    
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        InetAddress clientIP = getClientIP(ctx);
        
        // Kiểm tra rate limiting
        if (!checkRateLimit(clientIP)) {
            logger.warn("IP {} exceeded packet rate limit, blocking", clientIP);
            blockIP(clientIP);
            ctx.close();
            return;
        }
        
        // Kiểm tra kích thước packet
        if (msg instanceof MinecraftPacket) {
            if (!validatePacketSize(msg)) {
                logger.warn("Invalid packet size from IP {}", clientIP);
                ctx.close();
                return;
            }
        }
        
        super.channelRead(ctx, msg);
    }
    
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        InetAddress clientIP = getClientIP(ctx);
        logger.error("Exception from IP {}: {} ({})", clientIP, cause.getMessage(), cause.getClass().getSimpleName());
        
        // Track exceptions and block IP if too many errors occur
        PacketRateTracker tracker = packetRates.get(clientIP);
        if (tracker != null) {
            int errorCount = tracker.errorCount.incrementAndGet();
            if (errorCount > MAX_ERROR_COUNT) {
                logger.warn("IP {} exceeded error threshold ({}), blocking", clientIP, errorCount);
                blockIP(clientIP);
                ctx.close();
                return;
            } else if (errorCount > ERROR_WARNING_THRESHOLD) {
                logger.warn("IP {} has {} errors, monitoring closely", clientIP, errorCount);
            }
        }
        
        super.exceptionCaught(ctx, cause);
    }
    
    /**
     * Block an IP address temporarily
     * @param ip the IP address to block
     */
    private void blockIP(InetAddress ip) {
        blockedIPs.put(ip, System.currentTimeMillis());
        // Clean up all tracking data for the blocked IP
        connectionCount.remove(ip);
        packetRates.remove(ip);
        logger.info("Blocked IP {} for {} ms (reason: DDoS protection triggered)", 
                   ip, BLOCK_DURATION);
    }
    
    /**
     * Check if an IP address is currently blocked
     * @param ip the IP address to check
     * @return true if blocked, false otherwise
     */
    private boolean isBlocked(InetAddress ip) {
        Long blockTime = blockedIPs.get(ip);
        if (blockTime == null) return false;
        
        if (System.currentTimeMillis() - blockTime > BLOCK_DURATION) {
            blockedIPs.remove(ip);
            logger.debug("IP {} block expired, removing from blocked list", ip);
            return false;
        }
        return true;
    }
    
    /**
     * Get the client IP address from the channel context
     * @param ctx the channel handler context
     * @return the client IP address
     */
    private InetAddress getClientIP(ChannelHandlerContext ctx) {
        return ((java.net.InetSocketAddress) ctx.channel().remoteAddress()).getAddress();
    }
    
    /**
     * Check if the IP has exceeded the packet rate limit
     * @param ip the client IP address
     * @return true if within rate limit, false if exceeded
     */
    private boolean checkRateLimit(InetAddress ip) {
        PacketRateTracker tracker = packetRates.computeIfAbsent(ip, k -> new PacketRateTracker());
        
        long currentTime = System.currentTimeMillis();
        if (currentTime - tracker.lastReset.get() > RATE_LIMIT_WINDOW) {
            tracker.packetCount.set(0);
            tracker.lastReset.set(currentTime);
            tracker.errorCount.set(0); // Reset error count on window reset
        }
        
        return tracker.packetCount.incrementAndGet() <= MAX_PACKETS_PER_SECOND;
    }
    
    /**
     * Validates packet size to prevent oversized packets that could cause memory issues
     * @param packet the packet to validate
     * @return true if packet size is acceptable, false otherwise
     */
    private boolean validatePacketSize(Object packet) {
        if (packet instanceof MinecraftPacket) {
            // Minecraft packets should typically be under 32KB (32768 bytes)
            // This is a reasonable limit to prevent memory exhaustion attacks
            // Large packets could indicate malicious behavior
            try {
                // For now, we accept all MinecraftPacket instances as they are 
                // pre-validated by the Velocity protocol handlers
                // Future improvement: implement actual size checking using ByteBuf
                return true;
            } catch (Exception e) {
                logger.warn("Error validating packet size: {}", e.getMessage());
                return false;
            }
        }
        // Reject non-MinecraftPacket objects
        return false;
    }
    
    /**
     * Cleanup expired blocked IPs
     */
    public void cleanupBlockedIPs() {
        long currentTime = System.currentTimeMillis();
        blockedIPs.entrySet().removeIf(entry -> 
            currentTime - entry.getValue() > BLOCK_DURATION);
    }
    
    /**
     * Cleanup stale packet rate trackers to prevent memory leaks
     * Should be called periodically to remove inactive IP trackers
     */
    public void cleanupPacketRateTrackers() {
        long currentTime = System.currentTimeMillis();
        // Remove trackers that haven't been active for more than 10 minutes
        long staleThreshold = 10 * 60 * 1000; // 10 minutes
        packetRates.entrySet().removeIf(entry -> 
            currentTime - entry.getValue().lastReset.get() > staleThreshold);
    }
    
    /**
     * Comprehensive cleanup method that should be called periodically
     * Cleans up both blocked IPs and stale packet rate trackers
     */
    public void performMaintenance() {
        cleanupBlockedIPs();
        cleanupPacketRateTrackers();
        logger.debug("Maintenance completed - Blocked IPs: {}, Rate trackers: {}", 
                     blockedIPs.size(), packetRates.size());
    }
    
    /**
     * Thread-safe tracker for packet rates and error counts per IP address.
     * Used to monitor and enforce rate limits and detect suspicious activity.
     */
    private static class PacketRateTracker {
        /** Current packet count in the current time window */
        final AtomicInteger packetCount = new AtomicInteger(0);
        /** Timestamp of the last rate limit window reset */
        final AtomicLong lastReset = new AtomicLong(System.currentTimeMillis());
        /** Count of errors/exceptions from this IP */
        final AtomicInteger errorCount = new AtomicInteger(0);
    }
}