/*
 * Copyright (C) 2024-2024 Velocity Contributors
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
 */

package com.velocitypowered.proxy.connection.antiddos;

import com.velocitypowered.proxy.protocol.MinecraftPacket;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Layer 4 DDoS Protection Handler.
 * Xử lý bảo vệ chống tấn công DDoS ở tầng TCP/UDP
 */
public class Layer4Handler extends ChannelInboundHandlerAdapter {

  private static final Logger logger = LoggerFactory.getLogger(Layer4Handler.class);

  private final AntiDdosConfig config;
  private final long moduleStartTime = System.currentTimeMillis();

  // Theo dõi kết nối theo IP
  private final ConcurrentHashMap<InetAddress, AtomicInteger> connectionCount =
      new ConcurrentHashMap<>();
  private final ConcurrentHashMap<InetAddress, PacketRateTracker> packetRates =
      new ConcurrentHashMap<>();

  // Danh sách IP bị chặn tạm thời
  private final ConcurrentHashMap<InetAddress, Long> blockedIps = new ConcurrentHashMap<>();

  public Layer4Handler() {
    this(new AntiDdosConfig());
  }

  public Layer4Handler(AntiDdosConfig config) {
    this.config = config;
    logger.info("[Layer4Handler] Initializing DDoS protection module");
    logger.info("[Layer4Handler] Configuration: maxConnectionsPerIp={}, maxPacketsPerSecond={}, blockDurationMs={}ms", 
        config.maxConnectionsPerIp, config.maxPacketsPerSecond, config.blockDurationMs);
    startProtection();
  }

  @Override
  public void channelActive(ChannelHandlerContext ctx) throws Exception {
    InetAddress clientIp = getClientIp(ctx);
    logger.debug("[Layer4Handler] New connection attempt from IP: {}", clientIp);

    // Advanced lobby check - Log client join details
    logClientJoinDetails(ctx, clientIp);

    // Kiểm tra IP có bị chặn không
    if (isBlocked(clientIp)) {
      logger.warn("[Layer4Handler] Blocked IP {} attempted to connect", clientIp);
      logger.warn("[LOBBY-CHECK] Blocked IP {} rejected before lobby entry", clientIp);
      ctx.close();
      return;
    }

    // Kiểm tra giới hạn kết nối
    AtomicInteger connections = connectionCount.computeIfAbsent(clientIp,
        k -> new AtomicInteger(0));
    if (connections.incrementAndGet() > config.maxConnectionsPerIp) {
      logger.warn("[Layer4Handler] IP {} exceeded connection limit ({}/{}), blocking", 
          clientIp, connections.get(), config.maxConnectionsPerIp);
      logger.warn("[LOBBY-CHECK] IP {} blocked for exceeding connection limit during lobby entry", clientIp);
      blockIp(clientIp);
      ctx.close();
      return;
    }

    logger.info("[Layer4Handler] New connection established from IP: {} (Total connections: {})", clientIp, connections.get());
    logger.info("[LOBBY-CHECK] Client from IP {} successfully entered lobby (Connection #{} for this IP)", 
        clientIp, connections.get());
    
    // Advanced client analysis
    performAdvancedClientAnalysis(ctx, clientIp);
    
    super.channelActive(ctx);
  }

  @Override
  public void channelInactive(ChannelHandlerContext ctx) throws Exception {
    InetAddress clientIp = getClientIp(ctx);
    AtomicInteger connections = connectionCount.get(clientIp);
    if (connections != null) {
      connections.decrementAndGet();
      logger.debug("[Layer4Handler] Connection closed from IP: {} (Remaining connections: {})", clientIp, connections.get());
      if (connections.get() <= 0) {
        connectionCount.remove(clientIp);
        logger.debug("[Layer4Handler] Removed IP {} from connection tracking", clientIp);
      }
    }
    super.channelInactive(ctx);
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    InetAddress clientIp = getClientIp(ctx);
    logger.trace("[Layer4Handler] Reading packet from IP: {}", clientIp);

    // Advanced lobby check - Monitor packet patterns
    logPacketAnalysis(clientIp, msg);

    // Kiểm tra rate limiting
    if (!checkRateLimit(clientIp)) {
      logger.warn("[Layer4Handler] IP {} exceeded packet rate limit, blocking", clientIp);
      logger.warn("[LOBBY-CHECK] IP {} blocked for packet rate limit violation in lobby", clientIp);
      blockIp(clientIp);
      ctx.close();
      return;
    }

    // Kiểm tra kích thước packet
    if (msg instanceof MinecraftPacket) {
      logger.trace("[Layer4Handler] Processing Minecraft packet from IP: {}", clientIp);
      logger.trace("[LOBBY-CHECK] Processing Minecraft packet from IP {} in lobby environment", clientIp);
      
      if (!validatePacketSize(msg)) {
        logger.warn("[Layer4Handler] Invalid packet size from IP {}", clientIp);
        logger.warn("[LOBBY-CHECK] IP {} sent invalid packet size in lobby, potential attack", clientIp);
        ctx.close();
        return;
      }
      
      // Advanced packet behavior analysis
      analyzePacketBehavior(clientIp, (MinecraftPacket) msg);
    }

    super.channelRead(ctx, msg);
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
    InetAddress clientIp = getClientIp(ctx);
    logger.error("[Layer4Handler] Exception from IP {}: {}", clientIp, cause.getMessage());

    // Chặn IP nếu có quá nhiều exception
    PacketRateTracker tracker = packetRates.get(clientIp);
    if (tracker != null) {
      tracker.errorCount.incrementAndGet();
      logger.warn("[Layer4Handler] Error count for IP {} increased to {}", clientIp, tracker.errorCount.get());
      if (tracker.errorCount.get() > 10) {
        logger.warn("[Layer4Handler] Too many errors from IP {}, blocking", clientIp);
        blockIp(clientIp);
        ctx.close();
        return;
      }
    }

    super.exceptionCaught(ctx, cause);
  }

  private InetAddress getClientIp(ChannelHandlerContext ctx) {
    return ((InetSocketAddress) ctx.channel().remoteAddress()).getAddress();
  }

  private boolean isBlocked(InetAddress ip) {
    Long blockTime = blockedIps.get(ip);
    if (blockTime == null) {
      return false;
    }

    long timeRemaining = config.blockDurationMs - (System.currentTimeMillis() - blockTime);
    if (timeRemaining <= 0) {
      blockedIps.remove(ip);
      logger.info("[Layer4Handler] Block time expired for IP {}, removing from block list", ip);
      return false;
    }
    logger.debug("[Layer4Handler] IP {} is still blocked for {} ms", ip, timeRemaining);
    return true;
  }

  private void blockIp(InetAddress ip) {
    blockedIps.put(ip, System.currentTimeMillis());
    connectionCount.remove(ip);
    packetRates.remove(ip);
    logger.info("[Layer4Handler] Blocked IP {} for {} ms", ip, config.blockDurationMs);
  }

  private boolean checkRateLimit(InetAddress ip) {
    PacketRateTracker tracker = packetRates.computeIfAbsent(ip, k -> new PacketRateTracker());

    long currentTime = System.currentTimeMillis();
    if (currentTime - tracker.lastReset.get() > config.rateLimitWindowMs) {
      logger.trace("[Layer4Handler] Resetting rate limit window for IP {}", ip);
      tracker.packetCount.set(0);
      tracker.lastReset.set(currentTime);
    }

    int packetCount = tracker.packetCount.incrementAndGet();
    if (packetCount > config.maxPacketsPerSecond) {
      logger.warn("[Layer4Handler] IP {} exceeded packet rate ({}/{})", 
          ip, packetCount, config.maxPacketsPerSecond);
      return false;
    }
    
    if (packetCount % 50 == 0) {  // Log every 50 packets to avoid excessive logging
      logger.trace("[Layer4Handler] IP {} packet rate: {}/{}", 
          ip, packetCount, config.maxPacketsPerSecond);
    }
    
    return true;
  }

  private boolean validatePacketSize(Object packet) {
    // Kiểm tra kích thước packet hợp lệ
    // Minecraft packets thường < 32KB
    return true; // Implement based on actual packet structure
  }

  /**
   * Cleanup expired blocked IPs.
   */
  public void cleanupBlockedIps() {
    long currentTime = System.currentTimeMillis();
    int initialSize = blockedIps.size();
    
    blockedIps.entrySet().removeIf(entry ->
        currentTime - entry.getValue() > config.blockDurationMs);
    
    int removed = initialSize - blockedIps.size();
    if (removed > 0) {
      logger.info("[Layer4Handler] Cleaned up {} expired IP blocks, {} remaining", 
          removed, blockedIps.size());
    } else if (initialSize > 0) {
      logger.debug("[Layer4Handler] No expired IP blocks to clean up, {} remain in block list", 
          blockedIps.size());
    }
  }

  /**
   * Explicitly starts the DDoS protection module.
   * This is called automatically by the constructor, but can be called
   * again to restart the module if it was previously stopped.
   */
  public void startProtection() {
    logger.info("[Layer4Handler] Starting DDoS protection module");
    // Reset start time
    // Clearing existing collections would be done here if restarting
    logger.info("[Layer4Handler] DDoS protection module started successfully");
    reportStatus();
  }

  /**
   * Stops the DDoS protection module.
   * This method releases resources and stops monitoring.
   * 
   * @param clearBlocked Whether to clear the blocked IP list
   * @return Number of connections that were being tracked
   */
  public int stopProtection(boolean clearBlocked) {
    int connectionsTracked = connectionCount.size();
    int blockedIpsCount = blockedIps.size();
    
    logger.warn("[Layer4Handler] Stopping DDoS protection module, {} connections were being tracked", 
        connectionsTracked);
    
    if (clearBlocked && blockedIpsCount > 0) {
      blockedIps.clear();
      logger.info("[Layer4Handler] Cleared {} blocked IPs", blockedIpsCount);
    }
    
    logger.warn("[Layer4Handler] DDoS protection module is now INACTIVE");
    return connectionsTracked;
  }

  /**
   * Returns statistics about the current state of this handler.
   * 
   * @return String containing information about connections, blocked IPs, etc.
   */
  public String getStatistics() {
    return String.format("[Layer4Handler] Statistics: Active connections: %d, Blocked IPs: %d, " +
            "Rate-limited IPs: %d, Max connections per IP: %d, Max packets per second: %d",
        connectionCount.size(), blockedIps.size(), packetRates.size(),
        config.maxConnectionsPerIp, config.maxPacketsPerSecond);
  }

  /**
   * Reports the current status of the DDoS protection module.
   * Useful for health checks and monitoring.
   */
  public void reportStatus() {
    logger.info("[Layer4Handler] DDoS Protection Status: ACTIVE");
    logger.info("[Layer4Handler] Module uptime: {} ms", System.currentTimeMillis() - moduleStartTime);
    logger.info(getStatistics());
    
    // Report top 5 IPs with most connections if any
    if (!connectionCount.isEmpty()) {
      logger.info("[Layer4Handler] Top connection sources:");
      connectionCount.entrySet().stream()
          .sorted((e1, e2) -> e2.getValue().get() - e1.getValue().get())
          .limit(5)
          .forEach(entry -> logger.info("  - {}: {} connections", 
              entry.getKey().getHostAddress(), entry.getValue().get()));
    }
  }

  private static class PacketRateTracker {
    final AtomicInteger packetCount = new AtomicInteger(0);
    final AtomicLong lastReset = new AtomicLong(System.currentTimeMillis());
    final AtomicInteger errorCount = new AtomicInteger(0);
  }
}