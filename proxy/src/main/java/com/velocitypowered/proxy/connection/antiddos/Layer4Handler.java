package com.velocitypowered.proxy.connection.antiddos;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.proxy.connection.MinecraftConnection;
import com.velocitypowered.proxy.protocol.packet.*;
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
 * Xử lý bảo vệ chống tấn công DDoS ở tầng TCP/UDP
 */
public class Layer4Handler extends ChannelInboundHandlerAdapter {
    
    private static final Logger logger = LoggerFactory.getLogger(Layer4Handler.class);
    
    // Giới hạn kết nối per IP
    private static final int MAX_CONNECTIONS_PER_IP = 5;
    private static final int MAX_PACKETS_PER_SECOND = 100;
    private static final long RATE_LIMIT_WINDOW = 1000; // 1 giây
    
    // Theo dõi kết nối theo IP
    private final ConcurrentHashMap<InetAddress, AtomicInteger> connectionCount = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<InetAddress, PacketRateTracker> packetRates = new ConcurrentHashMap<>();
    
    // Danh sách IP bị chặn tạm thời
    private final ConcurrentHashMap<InetAddress, Long> blockedIPs = new ConcurrentHashMap<>();
    private static final long BLOCK_DURATION = 300000; // 5 phút
    
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
        if (msg instanceof Packet) {
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
        logger.error("Exception from IP {}: {}", clientIP, cause.getMessage());
        
        // Chặn IP nếu có quá nhiều exception
        PacketRateTracker tracker = packetRates.get(clientIP);
        if (tracker != null) {
            tracker.errorCount.incrementAndGet();
            if (tracker.errorCount.get() > 10) {
                blockIP(clientIP);
                ctx.close();
                return;
            }
        }
        
        super.exceptionCaught(ctx, cause);
    }
    
    private InetAddress getClientIP(ChannelHandlerContext ctx) {
        return ((java.net.InetSocketAddress) ctx.channel().remoteAddress()).getAddress();
    }
    
    private boolean isBlocked(InetAddress ip) {
        Long blockTime = blockedIPs.get(ip);
        if (blockTime == null) return false;
        
        if (System.currentTimeMillis() - blockTime > BLOCK_DURATION) {
            blockedIPs.remove(ip);
            return false;
        }
        return true;
    }
    
    private void blockIP(InetAddress ip) {
        blockedIPs.put(ip, System.currentTimeMillis());
        connectionCount.remove(ip);
        packetRates.remove(ip);
        logger.info("Blocked IP {} for {} ms", ip, BLOCK_DURATION);
    }
    
    private boolean checkRateLimit(InetAddress ip) {
        PacketRateTracker tracker = packetRates.computeIfAbsent(ip, k -> new PacketRateTracker());
        
        long currentTime = System.currentTimeMillis();
        if (currentTime - tracker.lastReset.get() > RATE_LIMIT_WINDOW) {
            tracker.packetCount.set(0);
            tracker.lastReset.set(currentTime);
        }
        
        return tracker.packetCount.incrementAndGet() <= MAX_PACKETS_PER_SECOND;
    }
    
    private boolean validatePacketSize(Object packet) {
        // Kiểm tra kích thước packet hợp lệ
        // Minecraft packets thường < 32KB
        return true; // Implement based on actual packet structure
    }
    
    /**
     * Cleanup expired blocked IPs
     */
    public void cleanupBlockedIPs() {
        long currentTime = System.currentTimeMillis();
        blockedIPs.entrySet().removeIf(entry -> 
            currentTime - entry.getValue() > BLOCK_DURATION);
    }
    
    private static class PacketRateTracker {
        final AtomicInteger packetCount = new AtomicInteger(0);
        final AtomicLong lastReset = new AtomicLong(System.currentTimeMillis());
        final AtomicInteger errorCount = new AtomicInteger(0);
    }
}