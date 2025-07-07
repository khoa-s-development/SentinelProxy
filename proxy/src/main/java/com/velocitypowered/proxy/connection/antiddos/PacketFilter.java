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

import com.velocitypowered.proxy.protocol.MinecraftPacket;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelInboundHandlerAdapter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Packet filter for Minecraft protocol.
 * Filters packets based on size, content, and patterns.
 */
@Sharable
public class PacketFilter extends ChannelInboundHandlerAdapter {

  private static final Logger logger = LoggerFactory.getLogger(PacketFilter.class);

  private final PacketFilterConfig config;
  private final long moduleStartTime = System.currentTimeMillis();
  
  // Track last few packets from each client to detect repeats
  private final Map<InetAddress, RecentPackets> recentPacketsMap = new ConcurrentHashMap<>();
  
  // Statistics
  private final AtomicInteger totalFilteredPackets = new AtomicInteger(0);
  
  // Whitelisted packet types that should never be filtered
  private final Set<String> packetWhitelist = new HashSet<>();

  public PacketFilter() {
    this(new PacketFilterConfig());
  }
  
  public PacketFilter(PacketFilterConfig config) {
    this.config = config;
    
    if (config.packetWhitelist != null && !config.packetWhitelist.isEmpty()) {
      packetWhitelist.addAll(Arrays.asList(config.packetWhitelist.split(",")));
    }
    
    logger.info("[PacketFilter] Initializing packet filter");
    logger.info("[PacketFilter] Configuration: maxPacketSize={}, blockHarmful={}, blockRepeated={}", 
        config.maxPacketSize, config.blockHarmfulPatterns, config.blockRepeatedPackets);
    logger.info("[PacketFilter] Whitelisted packets: {}", packetWhitelist);
    logger.info("[PacketFilter] Packet filter is now active");
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    if (!(msg instanceof MinecraftPacket)) {
      super.channelRead(ctx, msg);
      return;
    }
    
    MinecraftPacket packet = (MinecraftPacket) msg;
    String packetType = packet.getClass().getSimpleName();
    InetAddress clientIp = getClientIp(ctx);
    
    // Never filter whitelisted packet types
    if (packetWhitelist.contains(packetType)) {
      logger.trace("[PacketFilter] Allowing whitelisted packet {} from {}", packetType, clientIp);
      super.channelRead(ctx, msg);
      return;
    }
    
    // Check for harmful patterns if enabled
    if (config.blockHarmfulPatterns && containsHarmfulPatterns(packet)) {
      logger.warn("[PacketFilter] Blocked harmful packet {} from {}", packetType, clientIp);
      totalFilteredPackets.incrementAndGet();
      return; // Drop packet
    }
    
    // Check for repeated identical packets if enabled
    if (config.blockRepeatedPackets && isRepeatedPacket(clientIp, packet)) {
      logger.warn("[PacketFilter] Blocked repeated packet {} from {}", packetType, clientIp);
      totalFilteredPackets.incrementAndGet();
      return; // Drop packet
    }
    
    // Implement size check if needed - this would require more detailed packet size info
    // For now we just log it
    logger.trace("[PacketFilter] Allowed packet {} from {}", packetType, clientIp);
    super.channelRead(ctx, msg);
  }
  
  @Override
  public void channelInactive(ChannelHandlerContext ctx) throws Exception {
    InetAddress clientIp = getClientIp(ctx);
    recentPacketsMap.remove(clientIp); // Cleanup
    super.channelInactive(ctx);
  }
  
  private boolean containsHarmfulPatterns(MinecraftPacket packet) {
    // This would contain logic to detect harmful patterns in packets
    // Such as buffer overflow attempts, chat message exploits, etc.
    // This is a placeholder - implement real detection here
    return false;
  }
  
  private boolean isRepeatedPacket(InetAddress clientIp, MinecraftPacket packet) {
    if (!config.blockRepeatedPackets) {
      return false;
    }
    
    RecentPackets recentPackets = recentPacketsMap.computeIfAbsent(
        clientIp, ip -> new RecentPackets(5));  // Track last 5 packets
    
    String packetType = packet.getClass().getSimpleName();
    return recentPackets.addAndCheckRepeated(packetType);
  }
  
  private InetAddress getClientIp(ChannelHandlerContext ctx) {
    return ((InetSocketAddress) ctx.channel().remoteAddress()).getAddress();
  }
  
  /**
   * Reports the current status of this module.
   */
  public void reportStatus() {
    logger.info("[PacketFilter] Status Report:");
    logger.info("[PacketFilter] - Module uptime: {} ms", System.currentTimeMillis() - moduleStartTime);
    logger.info("[PacketFilter] - Total filtered packets: {}", totalFilteredPackets.get());
    logger.info("[PacketFilter] - Currently tracking packets for {} clients", recentPacketsMap.size());
  }
  
  /**
   * Clean up old tracking data.
   */
  public void cleanup() {
    // We already clean up in channelInactive, but this handles any leaked instances
    int initialSize = recentPacketsMap.size();
    
    // Clean up entries older than 5 minutes
    long cutoffTime = System.currentTimeMillis() - (5 * 60 * 1000);
    recentPacketsMap.entrySet().removeIf(entry -> 
        entry.getValue().getLastUpdated() < cutoffTime);
    
    int removed = initialSize - recentPacketsMap.size();
    if (removed > 0) {
      logger.debug("[PacketFilter] Cleaned up {} stale packet trackers", removed);
    }
  }
  
  /**
   * Inner class to track recent packets from a client.
   */
  private static class RecentPackets {
    private final String[] packetTypes;
    private int index = 0;
    private long lastUpdated = System.currentTimeMillis();
    
    RecentPackets(int capacity) {
      this.packetTypes = new String[capacity];
    }
    
    boolean addAndCheckRepeated(String packetType) {
      // Check if this packet type appears in all slots
      boolean allSame = true;
      for (String existingType : packetTypes) {
        if (existingType != null && !existingType.equals(packetType)) {
          allSame = false;
          break;
        }
      }
      
      // Add the current packet
      packetTypes[index] = packetType;
      index = (index + 1) % packetTypes.length;
      lastUpdated = System.currentTimeMillis();
      
      return allSame && isFull();
    }
    
    boolean isFull() {
      for (String type : packetTypes) {
        if (type == null) {
          return false;
        }
      }
      return true;
    }
    
    long getLastUpdated() {
      return lastUpdated;
    }
  }
}