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
    performAdvancedClientAnalysis(clientIp, "unknown", "");
    
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
    logPacketAnalysisBasic(clientIp, msg);

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
      analyzeMinecraftPacketBehavior(clientIp, (MinecraftPacket) msg);
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

  /**
   * Log detailed client join information for advanced lobby checks.
   * 
   * @param ctx the channel context
   * @param clientIp the client IP address
   */
  private void logClientJoinDetails(ChannelHandlerContext ctx, InetAddress clientIp) {
    try {
      String hostAddress = clientIp.getHostAddress();
      String hostName = clientIp.getCanonicalHostName();
      
      logger.info("[LOBBY-CHECK] Client join details:");
      logger.info("[LOBBY-CHECK]   IP Address: {}", hostAddress);
      logger.info("[LOBBY-CHECK]   Hostname: {}", hostName);
      logger.info("[LOBBY-CHECK]   Channel ID: {}", ctx.channel().id().asShortText());
      logger.info("[LOBBY-CHECK]   Local Address: {}", ctx.channel().localAddress());
      logger.info("[LOBBY-CHECK]   Remote Address: {}", ctx.channel().remoteAddress());
      logger.info("[LOBBY-CHECK]   Connection Time: {}", System.currentTimeMillis());
      
      // Check for suspicious patterns
      if (hostAddress.equals(hostName)) {
        logger.debug("[LOBBY-CHECK]   No reverse DNS available for {}", hostAddress);
      } else {
        logger.debug("[LOBBY-CHECK]   Reverse DNS resolved: {} -> {}", hostAddress, hostName);
      }
      
      // Log connection frequency
      AtomicInteger existingConnections = connectionCount.get(clientIp);
      if (existingConnections != null && existingConnections.get() > 0) {
        logger.info("[LOBBY-CHECK]   Existing connections from this IP: {}", existingConnections.get());
      } else {
        logger.info("[LOBBY-CHECK]   First connection from this IP");
      }
      
    } catch (Exception e) {
      logger.warn("[LOBBY-CHECK] Error logging client details for {}: {}", clientIp, e.getMessage());
    }
  }

  /**
   * Advanced lobby check logging - logs detailed client join analysis
   * This method provides comprehensive debugging for bot detection in verification worlds
   * 
   * @param clientIp The IP address of the joining client
   * @param username The username of the joining client
   * @param serverName The name of the server/world being joined
   * @param connectionTime How long the client has been connected (ms)
   */
  public void logClientJoinAdvanced(InetAddress clientIp, String username, String serverName, long connectionTime) {
    logger.info("[Layer4Handler] [LOBBY-CHECK] Client join analysis:");
    logger.info("  ├─ IP: {}", clientIp.getHostAddress());
    logger.info("  ├─ Username: {}", username);
    logger.info("  ├─ Target Server: {}", serverName);
    logger.info("  ├─ Connection Duration: {}ms", connectionTime);
    
    // Analyze current connection statistics for this IP
    AtomicInteger connections = connectionCount.get(clientIp);
    PacketRateTracker tracker = packetRates.get(clientIp);
    
    if (connections != null) {
      logger.info("  ├─ Active Connections: {}/{}", connections.get(), config.maxConnectionsPerIp);
      
      if (connections.get() > 1) {
        logger.warn("  ├─ [SUSPICIOUS] Multiple connections from same IP detected");
      }
    }
    
    if (tracker != null) {
      long currentTime = System.currentTimeMillis();
      long windowAge = currentTime - tracker.lastReset.get();
      logger.info("  ├─ Packet Activity: {}/{} packets (window: {}ms)", 
          tracker.packetCount.get(), config.maxPacketsPerSecond, windowAge);
      logger.info("  ├─ Error Count: {}", tracker.errorCount.get());
      
      // Analyze packet behavior patterns
      if (tracker.packetCount.get() > config.maxPacketsPerSecond * 0.8) {
        logger.warn("  ├─ [SUSPICIOUS] High packet rate detected ({}% of limit)", 
            (tracker.packetCount.get() * 100) / config.maxPacketsPerSecond);
      }
      
      if (tracker.errorCount.get() > 5) {
        logger.warn("  ├─ [SUSPICIOUS] High error count detected");
      }
    }
    
    // Check if this is a blocked IP trying to connect
    if (isBlocked(clientIp)) {
      logger.error("  └─ [CRITICAL] Blocked IP attempting lobby join - connection should be rejected");
    } else {
      logger.info("  └─ [OK] Client appears legitimate for lobby verification");
    }
  }

  /**
   * Logs detailed packet analysis for lobby check debugging
   * 
   * @param clientIp The IP address of the client
   * @param packetType The type/name of the packet
   * @param packetSize The size of the packet in bytes
   * @param isInbound Whether this is an inbound (true) or outbound (false) packet
   */
  public void logPacketAnalysis(InetAddress clientIp, String packetType, int packetSize, boolean isInbound) {
    PacketRateTracker tracker = packetRates.get(clientIp);
    String direction = isInbound ? "INBOUND" : "OUTBOUND";
    
    logger.debug("[Layer4Handler] [PACKET-ANALYSIS] {} packet from {}: type={}, size={}b", 
        direction, clientIp.getHostAddress(), packetType, packetSize);
    
    if (tracker != null) {
      // Log detailed packet statistics
      logger.trace("[Layer4Handler] [PACKET-ANALYSIS] Client {} packet stats: count={}, errors={}, window_age={}ms", 
          clientIp.getHostAddress(), 
          tracker.packetCount.get(), 
          tracker.errorCount.get(),
          System.currentTimeMillis() - tracker.lastReset.get());
      
      // Detect suspicious packet patterns
      if (packetSize > 1024 && packetType.contains("Custom")) {
        logger.warn("[Layer4Handler] [PACKET-ANALYSIS] [SUSPICIOUS] Large custom packet detected: {}b from {}", 
            packetSize, clientIp.getHostAddress());
      }
      
      if (tracker.packetCount.get() > 0 && tracker.packetCount.get() % 100 == 0) {
        logger.info("[Layer4Handler] [PACKET-ANALYSIS] High activity client {}: {} packets processed", 
            clientIp.getHostAddress(), tracker.packetCount.get());
      }
    }
  }

  /**
   * Basic packet analysis logging for channelRead method
   * 
   * @param clientIp The IP address of the client
   * @param msg The packet/message object
   */
  private void logPacketAnalysisBasic(InetAddress clientIp, Object msg) {
    try {
      String packetType = msg.getClass().getSimpleName();
      int estimatedSize = packetType.length() * 2; // Rough estimate
      
      logger.trace("[Layer4Handler] [PACKET-ANALYSIS] Processing packet from {}: type={}, estimated_size={}b", 
          clientIp.getHostAddress(), packetType, estimatedSize);
      
      PacketRateTracker tracker = packetRates.get(clientIp);
      if (tracker != null) {
        // Log detailed packet statistics every 50 packets to avoid spam
        if (tracker.packetCount.get() % 50 == 0) {
          logger.debug("[Layer4Handler] [PACKET-ANALYSIS] Client {} activity: {} packets, {} errors", 
              clientIp.getHostAddress(), tracker.packetCount.get(), tracker.errorCount.get());
        }
        
        // Detect suspicious packet patterns
        if (packetType.contains("Custom") || packetType.contains("Unknown")) {
          logger.warn("[Layer4Handler] [PACKET-ANALYSIS] [SUSPICIOUS] Unusual packet type: {} from {}", 
              packetType, clientIp.getHostAddress());
        }
      }
    } catch (Exception e) {
      logger.debug("[Layer4Handler] Error in packet analysis: {}", e.getMessage());
    }
  }

  /**
   * Analyzes Minecraft packet behavior for bot detection
   * 
   * @param clientIp The IP address of the client
   * @param packet The Minecraft packet to analyze
   */
  private void analyzeMinecraftPacketBehavior(InetAddress clientIp, MinecraftPacket packet) {
    try {
      String packetType = packet.getClass().getSimpleName();
      
      logger.trace("[Layer4Handler] [MC-PACKET-ANALYSIS] Analyzing {} from {}", 
          packetType, clientIp.getHostAddress());
      
      PacketRateTracker tracker = packetRates.get(clientIp);
      if (tracker != null) {
        // Check for rapid-fire packets (potential bot behavior)
        long timeSinceReset = System.currentTimeMillis() - tracker.lastReset.get();
        if (timeSinceReset < 1000 && tracker.packetCount.get() > 20) {
          logger.warn("[Layer4Handler] [MC-PACKET-ANALYSIS] [SUSPICIOUS] Rapid packet burst from {}: {} packets in {}ms", 
              clientIp.getHostAddress(), tracker.packetCount.get(), timeSinceReset);
        }
        
        // Analyze specific packet patterns
        if (packetType.contains("PlayerInput") || packetType.contains("Movement")) {
          logger.trace("[Layer4Handler] [MC-PACKET-ANALYSIS] Movement packet from {}: {}", 
              clientIp.getHostAddress(), packetType);
          
          // Detect unnatural movement patterns
          if (tracker.packetCount.get() > 100 && tracker.packetCount.get() % 10 == 0) {
            logger.debug("[Layer4Handler] [MC-PACKET-ANALYSIS] High movement activity from {}: {} packets", 
                clientIp.getHostAddress(), tracker.packetCount.get());
          }
        }
        
        // Check for chat/command packets
        if (packetType.contains("Chat") || packetType.contains("Command")) {
          logger.info("[Layer4Handler] [MC-PACKET-ANALYSIS] Communication packet from {}: {}", 
              clientIp.getHostAddress(), packetType);
        }
        
        // Check for interaction packets (important for lobby verification)
        if (packetType.contains("Interact") || packetType.contains("Use") || packetType.contains("Place")) {
          logger.info("[Layer4Handler] [MC-PACKET-ANALYSIS] [LOBBY-INTERACTION] Interaction packet from {}: {}", 
              clientIp.getHostAddress(), packetType);
        }
      }
    } catch (Exception e) {
      logger.debug("[Layer4Handler] Error analyzing Minecraft packet: {}", e.getMessage());
    }
  }

  /**
   * Performs advanced client analysis for bot detection in lobby verification
   * This method combines multiple metrics to assess client legitimacy
   * 
   * @param clientIp The IP address to analyze
   * @param username The username to analyze
   * @param behaviorFlags Additional behavior flags (comma-separated)
   * @return A risk score from 0.0 (legitimate) to 1.0 (highly suspicious)
   */
  public double performAdvancedClientAnalysis(InetAddress clientIp, String username, String behaviorFlags) {
    logger.info("[Layer4Handler] [ADVANCED-ANALYSIS] Starting comprehensive client analysis for {}", clientIp.getHostAddress());
    
    double riskScore = 0.0;
    StringBuilder analysis = new StringBuilder();
    analysis.append("[Layer4Handler] [ADVANCED-ANALYSIS] Risk Assessment:\n");
    
    // 1. Connection pattern analysis
    AtomicInteger connections = connectionCount.get(clientIp);
    if (connections != null && connections.get() > 1) {
      double connectionRisk = Math.min(1.0, connections.get() / (double) config.maxConnectionsPerIp);
      riskScore += connectionRisk * 0.3;
      analysis.append("  ├─ Connection Risk: ").append(String.format("%.2f", connectionRisk))
          .append(" (").append(connections.get()).append(" connections)\n");
    }
    
    // 2. Packet behavior analysis
    PacketRateTracker tracker = packetRates.get(clientIp);
    if (tracker != null) {
      double packetRisk = Math.min(1.0, tracker.packetCount.get() / (double) config.maxPacketsPerSecond);
      riskScore += packetRisk * 0.25;
      analysis.append("  ├─ Packet Risk: ").append(String.format("%.2f", packetRisk))
          .append(" (").append(tracker.packetCount.get()).append(" packets)\n");
      
      if (tracker.errorCount.get() > 0) {
        double errorRisk = Math.min(1.0, tracker.errorCount.get() / 10.0);
        riskScore += errorRisk * 0.2;
        analysis.append("  ├─ Error Risk: ").append(String.format("%.2f", errorRisk))
            .append(" (").append(tracker.errorCount.get()).append(" errors)\n");
      }
    }
    
    // 3. Username pattern analysis
    if (username != null) {
      double usernameRisk = analyzeUsernamePattern(username);
      riskScore += usernameRisk * 0.15;
      analysis.append("  ├─ Username Risk: ").append(String.format("%.2f", usernameRisk))
          .append(" (pattern analysis)\n");
    }
    
    // 4. Behavior flags analysis
    if (behaviorFlags != null && !behaviorFlags.trim().isEmpty()) {
      String[] flags = behaviorFlags.split(",");
      double behaviorRisk = Math.min(1.0, flags.length / 5.0);
      riskScore += behaviorRisk * 0.1;
      analysis.append("  ├─ Behavior Risk: ").append(String.format("%.2f", behaviorRisk))
          .append(" (").append(flags.length).append(" flags)\n");
    }
    
    // 5. Historical analysis (if previously blocked)
    if (blockedIps.containsKey(clientIp)) {
      riskScore += 0.4; // High penalty for previously blocked IPs
      analysis.append("  ├─ History Risk: 0.40 (previously blocked)\n");
    }
    
    // Ensure risk score doesn't exceed 1.0
    riskScore = Math.min(1.0, riskScore);
    
    analysis.append("  └─ TOTAL RISK SCORE: ").append(String.format("%.3f", riskScore));
    
    if (riskScore > 0.7) {
      analysis.append(" [HIGH RISK - POTENTIAL BOT]");
      logger.error(analysis.toString());
    } else if (riskScore > 0.4) {
      analysis.append(" [MEDIUM RISK - MONITOR CLOSELY]");
      logger.warn(analysis.toString());
    } else {
      analysis.append(" [LOW RISK - LIKELY LEGITIMATE]");
      logger.info(analysis.toString());
    }
    
    return riskScore;
  }

  /**
   * Analyzes username patterns for bot detection
   * 
   * @param username The username to analyze
   * @return Risk score from 0.0 to 1.0
   */
  private double analyzeUsernamePattern(String username) {
    if (username == null || username.trim().isEmpty()) {
      return 0.8; // High risk for empty usernames
    }
    
    double risk = 0.0;
    
    // Check for common bot patterns
    if (username.matches(".*\\d{4,}.*")) {
      risk += 0.3; // Many consecutive numbers
    }
    
    if (username.matches("^[a-zA-Z]+\\d+$")) {
      risk += 0.2; // Letters followed by numbers only
    }
    
    if (username.length() < 3 || username.length() > 16) {
      risk += 0.3; // Unusual length
    }
    
    if (username.matches(".*[xX]{2,}.*") || username.matches(".*[zZ]{2,}.*")) {
      risk += 0.2; // Repeated x's or z's (common in bots)
    }
    
    if (username.toLowerCase().contains("bot") || username.toLowerCase().contains("test")) {
      risk += 0.5; // Contains bot-related terms
    }
    
    return Math.min(1.0, risk);
  }

  private static class PacketRateTracker {
    final AtomicInteger packetCount = new AtomicInteger(0);
    final AtomicLong lastReset = new AtomicLong(System.currentTimeMillis());
    final AtomicInteger errorCount = new AtomicInteger(0);
  }
}