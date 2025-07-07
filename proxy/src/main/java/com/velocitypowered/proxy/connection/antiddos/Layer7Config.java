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

import java.util.concurrent.TimeUnit;

/**
 * Configuration for the Layer7Handler.
 */
public class Layer7Config {
  // Thresholds for various attacks
  public final int maxLoginAttemptsPerIp;
  public final int maxPacketTypePerSecond;
  public final int maxServerListPingsPerIp;
  public final long blockDurationMs;
  
  // Protocol-specific options
  public final boolean detectProtocolViolations;
  public final boolean trackPacketPatterns;

  
  /**
   * Create a default configuration.
   */
  public Layer7Config() {
    // Default values - adjust as needed for your server
    this.maxLoginAttemptsPerIp = 20;
    this.maxPacketTypePerSecond = 100;
    this.maxServerListPingsPerIp = 3;
    this.blockDurationMs = TimeUnit.MINUTES.toMillis(5);
    this.detectProtocolViolations = true;
    this.trackPacketPatterns = true;
  }

  /**
   * Create a configuration with custom parameters.
   *
   * @param builder The builder to create the configuration from
   */
  private Layer7Config(Builder builder) {
    this.maxLoginAttemptsPerIp = builder.maxLoginAttemptsPerIp;
    this.maxPacketTypePerSecond = builder.maxPacketTypePerSecond;
    this.maxServerListPingsPerIp = builder.maxServerListPingsPerIp;
    this.blockDurationMs = builder.blockDurationMs;
    this.detectProtocolViolations = builder.detectProtocolViolations;
    this.trackPacketPatterns = builder.trackPacketPatterns;
  }
  
  /**
   * Creates a new builder for Layer7Config.
   * 
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }
  
  /**
   * Builder for Layer7Config.
   */
  public static class Builder {
    private int maxLoginAttemptsPerIp = 20;
    private int maxPacketTypePerSecond = 100;
    private int maxServerListPingsPerIp = 3;
    private long blockDurationMs = TimeUnit.MINUTES.toMillis(5);
    private boolean detectProtocolViolations = true;
    private boolean trackPacketPatterns = true;
    
    private Builder() {
      // Private constructor
    }
    
    public Builder maxLoginAttemptsPerIp(int maxLoginAttemptsPerIp) {
      this.maxLoginAttemptsPerIp = maxLoginAttemptsPerIp;
      return this;
    }
    
    public Builder maxPacketTypePerSecond(int maxPacketTypePerSecond) {
      this.maxPacketTypePerSecond = maxPacketTypePerSecond;
      return this;
    }
    
    public Builder maxServerListPingsPerIp(int maxServerListPingsPerIp) {
      this.maxServerListPingsPerIp = maxServerListPingsPerIp;
      return this;
    }
    
    public Builder blockDurationMs(long blockDurationMs) {
      this.blockDurationMs = blockDurationMs;
      return this;
    }
    
    public Builder detectProtocolViolations(boolean detectProtocolViolations) {
      this.detectProtocolViolations = detectProtocolViolations;
      return this;
    }
    
    public Builder trackPacketPatterns(boolean trackPacketPatterns) {
      this.trackPacketPatterns = trackPacketPatterns;
      return this;
    }
    
    // Anti-Bot functionality moved to AntiBot class
    
    public Layer7Config build() {
      return new Layer7Config(this);
    }
  }
}
