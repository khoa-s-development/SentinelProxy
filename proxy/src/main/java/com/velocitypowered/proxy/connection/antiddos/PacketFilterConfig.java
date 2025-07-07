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

/**
 * Configuration for the PacketFilter.
 */
public class PacketFilterConfig {
  // Maximum allowed packet size in bytes
  public final int maxPacketSize;
  
  // Whether to block harmful packet patterns
  public final boolean blockHarmfulPatterns;
  
  // Whether to block repeated identical packets
  public final boolean blockRepeatedPackets;
  
  // Comma-separated list of packet names that should never be filtered
  public final String packetWhitelist;
  
  /**
   * Create a default configuration.
   */
  public PacketFilterConfig() {
    // Default values
    this.maxPacketSize = 32768; // 32KB
    this.blockHarmfulPatterns = true;
    this.blockRepeatedPackets = true;
    this.packetWhitelist = "Handshake,ServerPing,LoginStart";
  }
  
  /**
   * Create a configuration with custom parameters.
   *
   * @param maxPacketSize Maximum allowed packet size in bytes
   * @param blockHarmfulPatterns Whether to block harmful packet patterns
   * @param blockRepeatedPackets Whether to block repeated identical packets
   * @param packetWhitelist Comma-separated list of packet names that should never be filtered
   */
  public PacketFilterConfig(int maxPacketSize, boolean blockHarmfulPatterns,
                         boolean blockRepeatedPackets, String packetWhitelist) {
    this.maxPacketSize = maxPacketSize;
    this.blockHarmfulPatterns = blockHarmfulPatterns;
    this.blockRepeatedPackets = blockRepeatedPackets;
    this.packetWhitelist = packetWhitelist;
  }
}
