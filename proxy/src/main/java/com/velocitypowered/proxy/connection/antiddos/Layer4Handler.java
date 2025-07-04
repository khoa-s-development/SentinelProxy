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
  }

  @Override
  public void channelActive(ChannelHandlerContext ctx) throws Exception {
    InetAddress clientIp = getClientIp(ctx);

    // Kiểm tra IP có bị chặn không
    if (isBlocked(clientIp)) {
      logger.warn("Blocked IP {} attempted to connect", clientIp);
      ctx.close();
      return;
    }

    // Kiểm tra giới hạn kết nối
    AtomicInteger connections = connectionCount.computeIfAbsent(clientIp,
        k -> new AtomicInteger(0));
    if (connections.incrementAndGet() > config.maxConnectionsPerIp) {
      logger.warn("IP {} exceeded connection limit, blocking", clientIp);
      blockIp(clientIp);
      ctx.close();
      return;
    }

    logger.debug("New connection from IP: {} (Total: {})", clientIp, connections.get());
    super.channelActive(ctx);
  }

  @Override
  public void channelInactive(ChannelHandlerContext ctx) throws Exception {
    InetAddress clientIp = getClientIp(ctx);
    AtomicInteger connections = connectionCount.get(clientIp);
    if (connections != null) {
      connections.decrementAndGet();
      if (connections.get() <= 0) {
        connectionCount.remove(clientIp);
      }
    }
    super.channelInactive(ctx);
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    InetAddress clientIp = getClientIp(ctx);

    // Kiểm tra rate limiting
    if (!checkRateLimit(clientIp)) {
      logger.warn("IP {} exceeded packet rate limit, blocking", clientIp);
      blockIp(clientIp);
      ctx.close();
      return;
    }

    // Kiểm tra kích thước packet
    if (msg instanceof MinecraftPacket) {
      if (!validatePacketSize(msg)) {
        logger.warn("Invalid packet size from IP {}", clientIp);
        ctx.close();
        return;
      }
    }

    super.channelRead(ctx, msg);
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
    InetAddress clientIp = getClientIp(ctx);
    logger.error("Exception from IP {}: {}", clientIp, cause.getMessage());

    // Chặn IP nếu có quá nhiều exception
    PacketRateTracker tracker = packetRates.get(clientIp);
    if (tracker != null) {
      tracker.errorCount.incrementAndGet();
      if (tracker.errorCount.get() > 10) {
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

    if (System.currentTimeMillis() - blockTime > config.blockDurationMs) {
      blockedIps.remove(ip);
      return false;
    }
    return true;
  }

  private void blockIp(InetAddress ip) {
    blockedIps.put(ip, System.currentTimeMillis());
    connectionCount.remove(ip);
    packetRates.remove(ip);
    logger.info("Blocked IP {} for {} ms", ip, config.blockDurationMs);
  }

  private boolean checkRateLimit(InetAddress ip) {
    PacketRateTracker tracker = packetRates.computeIfAbsent(ip, k -> new PacketRateTracker());

    long currentTime = System.currentTimeMillis();
    if (currentTime - tracker.lastReset.get() > config.rateLimitWindowMs) {
      tracker.packetCount.set(0);
      tracker.lastReset.set(currentTime);
    }

    return tracker.packetCount.incrementAndGet() <= config.maxPacketsPerSecond;
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
    blockedIps.entrySet().removeIf(entry ->
        currentTime - entry.getValue() > config.blockDurationMs);
  }

  private static class PacketRateTracker {
    final AtomicInteger packetCount = new AtomicInteger(0);
    final AtomicLong lastReset = new AtomicLong(System.currentTimeMillis());
    final AtomicInteger errorCount = new AtomicInteger(0);
  }
}