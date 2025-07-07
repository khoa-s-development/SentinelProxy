/*
 * Copyright (C) 2025 Velocity Contributors
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

import com.velocitypowered.api.event.connection.PluginMessageEvent;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.protocol.MinecraftPacket;

import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Layer 7 DDoS Protection Handler.
 * Focuses on Minecraft protocol-specific protection for TCP/UDP traffic.
 */
@Sharable
public class Layer7Handler extends ChannelInboundHandlerAdapter {

  private static final Logger logger = LoggerFactory.getLogger(Layer7Handler.class);
  private final long moduleStartTime = System.currentTimeMillis();
  
  // Configuration
  private final Layer7Config config;
  
  // Connection tracking
  private final Map<InetAddress, ClientTracker> clientTrackers = new ConcurrentHashMap<>();
  private final Map<InetAddress, Long> blockedIps = new ConcurrentHashMap<>();
  
  // Statistics
  private final AtomicInteger totalBlockedConnections = new AtomicInteger(0);
  private final AtomicInteger totalDetectedAttacks = new AtomicInteger(0);
  private final AtomicInteger totalDetectedBots = new AtomicInteger(0);
  
  // Reference to the server
  private final VelocityServer server;

  public Layer7Handler(VelocityServer server) {
    this(server, new Layer7Config());
  }
  
  public Layer7Handler(VelocityServer server, Layer7Config config) {
    this.server = server;
    this.config = config;
    
    logger.info("[Layer7Handler] Initializing Minecraft protocol protection module");
    logger.info("[Layer7Handler] Configuration: maxLoginAttempts={}, maxPacketTypePerSecond={}, " +
        "maxServerListPings={}, blockDuration={}ms",
        config.maxLoginAttemptsPerIp, config.maxPacketTypePerSecond, 
        config.maxServerListPingsPerIp, config.blockDurationMs);
    logger.info("[Layer7Handler] Protocol violation detection: {}", 
        config.detectProtocolViolations ? "enabled" : "disabled");
    
    logger.info("[Layer7Handler] Advanced Minecraft protocol protection is now active");
  }

  @Override
  public void channelActive(ChannelHandlerContext ctx) throws Exception {
    InetAddress clientIp = getClientIp(ctx);
    logger.debug("[Layer7Handler] New Minecraft connection from {}", clientIp);
    
    if (isBlocked(clientIp)) {
      logger.warn("[Layer7Handler] Blocked IP {} attempted to connect", clientIp);
      totalBlockedConnections.incrementAndGet();
      ctx.close();
      return;
    }
    
    getOrCreateTracker(clientIp);
    super.channelActive(ctx);
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    if (!(msg instanceof MinecraftPacket)) {
      super.channelRead(ctx, msg);
      return;
    }
    
    InetAddress clientIp = getClientIp(ctx);
    MinecraftPacket packet = (MinecraftPacket) msg;
    ClientTracker tracker = getOrCreateTracker(clientIp);
    
    // Check if this is a protocol violation
    if (checkForProtocolViolation(ctx, clientIp, packet, tracker)) {
      return;
    }
    
    // Update packet type statistics
    String packetType = packet.getClass().getSimpleName();
    tracker.recordPacketType(packetType);
    
    // Check for packet flooding
    if (checkForPacketFlooding(ctx, clientIp, packet, tracker)) {
      return;
    }
    
    // Record login attempts
    if (isLoginPacket(packet)) {
      tracker.recordLoginAttempt();
      
      // Check for login brute force
      if (tracker.getLoginAttempts() > config.maxLoginAttemptsPerIp) {
        logger.warn("[Layer7Handler] IP {} exceeded login attempts limit ({}), blocking", 
            clientIp, tracker.getLoginAttempts());
        blockIp(clientIp, "Login brute force");
        ctx.close();
        return;
      }
    }
    
    // Handle server list ping packets
    if (isServerListPingPacket(packet)) {
      tracker.recordServerListPing();
      
      // Check for server list ping spam
      if (tracker.getServerListPings() > config.maxServerListPingsPerIp) {
        logger.warn("[Layer7Handler] IP {} exceeded server list ping limit ({}), blocking", 
            clientIp, tracker.getServerListPings());
        blockIp(clientIp, "Server list ping spam");
        ctx.close();
        return;
      }
    }
    
    super.channelRead(ctx, msg);
  }
  
  @Override
  public void channelInactive(ChannelHandlerContext ctx) throws Exception {
    InetAddress clientIp = getClientIp(ctx);
    logger.debug("[Layer7Handler] Minecraft connection closed from {}", clientIp);
    
    // We don't remove the tracker here to maintain history
    // but we may want to clean them up periodically
    
    super.channelInactive(ctx);
  }
  
  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
    InetAddress clientIp = getClientIp(ctx);
    logger.warn("[Layer7Handler] Exception from client {}: {}", clientIp, cause.getMessage());
    
    ClientTracker tracker = clientTrackers.get(clientIp);
    if (tracker != null) {
      tracker.recordException();
      
      // Too many exceptions might indicate an attack
      if (tracker.getExceptionCount() > 5) {
        logger.warn("[Layer7Handler] IP {} triggered too many exceptions ({}), blocking", 
            clientIp, tracker.getExceptionCount());
        blockIp(clientIp, "Too many exceptions");
        ctx.close();
        return;
      }
    }
    
    super.exceptionCaught(ctx, cause);
  }
  
  private boolean checkForProtocolViolation(ChannelHandlerContext ctx, InetAddress clientIp, 
                                           MinecraftPacket packet, ClientTracker tracker) {
    // If protocol violation detection is disabled, skip this check
    if (!config.detectProtocolViolations) {
      return false;
    }
    
    // Add Minecraft protocol validation here
    // This checks if clients are sending packets in the correct order
    // For example, you cannot send gameplay packets during handshaking
    
    // Just a stub for now - implement actual protocol state checks
    boolean isViolation = false;
    
    if (isViolation) {
      logger.warn("[Layer7Handler] Protocol violation from IP {}, blocking", clientIp);
      blockIp(clientIp, "Protocol violation");
      ctx.close();
      return true;
    }
    
    return false;
  }
  
  private boolean checkForPacketFlooding(ChannelHandlerContext ctx, InetAddress clientIp, 
                                        MinecraftPacket packet, ClientTracker tracker) {
    String packetType = packet.getClass().getSimpleName();
    int packetCount = tracker.getPacketTypeCount(packetType);
    
    if (packetCount > config.maxPacketTypePerSecond) {
      logger.warn("[Layer7Handler] IP {} is flooding with {} packets ({}/sec), blocking", 
          clientIp, packetType, packetCount);
      blockIp(clientIp, "Packet flooding: " + packetType);
      ctx.close();
      return true;
    }
    
    return false;
  }
  
  private boolean isLoginPacket(MinecraftPacket packet) {
    // Implement check for login packets
    String packetName = packet.getClass().getSimpleName();
    return packetName.contains("Login") || packetName.contains("Encryption");
  }
  
  private boolean isServerListPingPacket(MinecraftPacket packet) {
    // Implement check for server list ping packets
    String packetName = packet.getClass().getSimpleName();
    return packetName.contains("ServerPing") || packetName.contains("StatusRequest");
  }
  
  private InetAddress getClientIp(ChannelHandlerContext ctx) {
    return ((InetSocketAddress) ctx.channel().remoteAddress()).getAddress();
  }
  
  private ClientTracker getOrCreateTracker(InetAddress clientIp) {
    return clientTrackers.computeIfAbsent(clientIp, ip -> new ClientTracker());
  }
  
  private boolean isBlocked(InetAddress ip) {
    Long blockTime = blockedIps.get(ip);
    if (blockTime == null) {
      return false;
    }
    
    long timeRemaining = config.blockDurationMs - (System.currentTimeMillis() - blockTime);
    if (timeRemaining <= 0) {
      blockedIps.remove(ip);
      logger.info("[Layer7Handler] Block time expired for IP {}, removing from block list", ip);
      return false;
    }
    
    return true;
  }
  
  private void blockIp(InetAddress ip, String reason) {
    blockedIps.put(ip, System.currentTimeMillis());
    totalDetectedAttacks.incrementAndGet();
    logger.info("[Layer7Handler] Blocked IP {} for {}ms due to: {}", 
        ip, config.blockDurationMs, reason);
  }
  
  /**
   * Clean up expired IP blocks and old client trackers.
   */
  public void cleanup() {
    long currentTime = System.currentTimeMillis();
    int removedBlocks = 0;
    
    // Clean up expired blocks
    for (Map.Entry<InetAddress, Long> entry : blockedIps.entrySet()) {
      if (currentTime - entry.getValue() > config.blockDurationMs) {
        blockedIps.remove(entry.getKey());
        removedBlocks++;
      }
    }
    
    // Clean up old trackers (older than 30 minutes)
    long cutoffTime = currentTime - TimeUnit.MINUTES.toMillis(30);
    int removedTrackers = 0;
    
    for (Map.Entry<InetAddress, ClientTracker> entry : clientTrackers.entrySet()) {
      if (entry.getValue().getLastActivity() < cutoffTime) {
        clientTrackers.remove(entry.getKey());
        removedTrackers++;
      }
    }
    
    logger.debug("[Layer7Handler] Cleanup: removed {} expired blocks and {} inactive trackers",
        removedBlocks, removedTrackers);
  }
  
  /**
   * Reports the current status of this module.
   */
  public void reportStatus() {
    int activeConnections = clientTrackers.size();
    int blockedIpsCount = blockedIps.size();
    
    logger.info("[Layer7Handler] Status Report:");
    logger.info("[Layer7Handler] - Module uptime: {} ms", System.currentTimeMillis() - moduleStartTime);
    logger.info("[Layer7Handler] - Active client trackers: {}", activeConnections);
    logger.info("[Layer7Handler] - Currently blocked IPs: {}", blockedIpsCount);
    logger.info("[Layer7Handler] - Total blocked connections: {}", totalBlockedConnections.get());
    logger.info("[Layer7Handler] - Total detected attacks: {}", totalDetectedAttacks.get());
    
    // Report top offenders if any
    if (!clientTrackers.isEmpty()) {
      logger.info("[Layer7Handler] Top client activity (top 5):");
      clientTrackers.entrySet().stream()
          .sorted((e1, e2) -> e2.getValue().getTotalPackets() - e1.getValue().getTotalPackets())
          .limit(5)
          .forEach(entry -> logger.info("  - {}: {} packets, {} logins, {} server pings", 
              entry.getKey().getHostAddress(), 
              entry.getValue().getTotalPackets(),
              entry.getValue().getLoginAttempts(),
              entry.getValue().getServerListPings()));
    }
  }
  
  /**
   * Handle plugin message if needed
   */
  private void handlePluginMessage(PluginMessageEvent event) {
    // No need to handle plugin messages in Layer7Handler
    // Anti-Bot functionality is now handled by the dedicated AntiBot class
  }
  
  /**
   * Inner class to track per-client activity.
   */
  private static class ClientTracker {
    private final Map<String, AtomicInteger> packetTypeCounts = new ConcurrentHashMap<>();
    private final AtomicInteger loginAttempts = new AtomicInteger(0);
    private final AtomicInteger serverListPings = new AtomicInteger(0);
    private final AtomicInteger exceptionCount = new AtomicInteger(0);
    private final AtomicInteger totalPackets = new AtomicInteger(0);
    
    private long lastActivity = System.currentTimeMillis();
    private long lastReset = System.currentTimeMillis();
    
    void recordPacketType(String packetType) {
      updateActivity();
      resetCountsIfNeeded();
      
      packetTypeCounts.computeIfAbsent(packetType, k -> new AtomicInteger(0)).incrementAndGet();
      totalPackets.incrementAndGet();
    }
    
    int getPacketTypeCount(String packetType) {
      return packetTypeCounts.getOrDefault(packetType, new AtomicInteger(0)).get();
    }
    
    void recordLoginAttempt() {
      updateActivity();
      loginAttempts.incrementAndGet();
    }
    
    int getLoginAttempts() {
      return loginAttempts.get();
    }
    
    void recordServerListPing() {
      updateActivity();
      serverListPings.incrementAndGet();
    }
    
    int getServerListPings() {
      return serverListPings.get();
    }
    
    void recordException() {
      updateActivity();
      exceptionCount.incrementAndGet();
    }
    
    int getExceptionCount() {
      return exceptionCount.get();
    }
    
    int getTotalPackets() {
      return totalPackets.get();
    }
    
    long getLastActivity() {
      return lastActivity;
    }
    
    private void updateActivity() {
      lastActivity = System.currentTimeMillis();
    }
    
    private void resetCountsIfNeeded() {
      long currentTime = System.currentTimeMillis();
      // Reset packet type counts every second
      if (currentTime - lastReset > 1000) {
        packetTypeCounts.clear();
        lastReset = currentTime;
      }
    }
  }
  
  // Anti-bot functionality moved to AntiBot class
}
