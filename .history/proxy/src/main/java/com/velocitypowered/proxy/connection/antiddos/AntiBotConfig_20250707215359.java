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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Configuration for AntiBot system.
 */
public class AntiBotConfig {
  private final boolean enabled;
  private final boolean kickEnabled;
  private final boolean debugMode;
  private final int kickThreshold;
  private final String kickMessage;
  private final boolean checkOnlyFirstJoin;
  private final int verificationTimeout;
  
  // Individual check configurations
  private final boolean gravityCheckEnabled;
  private final boolean hitboxCheckEnabled;
  private final boolean yawCheckEnabled;
  private final boolean clientBrandCheckEnabled;
  
  // Mini-world check configuration
  private final boolean miniWorldCheckEnabled;
  private final int miniWorldDuration;
  private final int miniWorldMinMovements;
  private final double miniWorldMinDistance;
  
  // Connection rate limiting
  private final boolean connectionRateLimitEnabled;
  private final int connectionRateLimit;
  private final long connectionRateWindowMs;
  private final long throttleDurationMs;
  
  // Username pattern check
  private final boolean usernamePatternCheckEnabled;
  private final int usernamePatternThreshold;
  
  // Latency check
  private final boolean latencyCheckEnabled;
  private final long maxLatencyMs;
  
  // DNS and IP check
  private final boolean dnsCheckEnabled;
  private final boolean allowDirectIpConnections;
  private final Set<String> allowedDomains;
  
  // Allowed client brands
  private final Set<String> allowedBrands;
  
  // Username pattern fields
  private final Set<String> usernamePatterns;
  private final boolean sequentialCharCheck;
  private final int sequentialCharThreshold;
  private final boolean randomDistributionCheck;
  
  // Additional rate limiting fields
  private final long rateLimitWindowMillis;
  private final int rateLimitThreshold;
  
  // DNS check fields 
  private final Set<String> excludedIps;
  
  // Latency check additional fields
  private final long minLatencyThreshold;
  private final long maxLatencyThreshold;
  
  // Cleanup settings
  private final int cleanupThresholdMinutes;

  private AntiBotConfig(Builder builder) {
    this.enabled = builder.enabled;
    this.kickEnabled = builder.kickEnabled;
    this.debugMode = builder.debugMode;
    this.kickThreshold = builder.kickThreshold;
    this.kickMessage = builder.kickMessage;
    this.checkOnlyFirstJoin = builder.checkOnlyFirstJoin;
    this.verificationTimeout = builder.verificationTimeout;
    this.gravityCheckEnabled = builder.gravityCheckEnabled;
    this.hitboxCheckEnabled = builder.hitboxCheckEnabled;
    this.yawCheckEnabled = builder.yawCheckEnabled;
    this.clientBrandCheckEnabled = builder.clientBrandCheckEnabled;
    this.miniWorldCheckEnabled = builder.miniWorldCheckEnabled;
    this.connectionRateLimitEnabled = builder.connectionRateLimitEnabled;
    this.connectionRateLimit = builder.connectionRateLimit;
    this.connectionRateWindowMs = builder.connectionRateWindowMs;
    this.throttleDurationMs = builder.throttleDurationMs;
    this.usernamePatternCheckEnabled = builder.usernamePatternCheckEnabled;
    this.usernamePatternThreshold = builder.usernamePatternThreshold;
    this.latencyCheckEnabled = builder.latencyCheckEnabled;
    this.maxLatencyMs = builder.maxLatencyMs;
    this.dnsCheckEnabled = builder.dnsCheckEnabled;
    this.allowDirectIpConnections = builder.allowDirectIpConnections;
    this.allowedDomains = Collections.unmodifiableSet(new HashSet<>(builder.allowedDomains));
    this.miniWorldDuration = builder.miniWorldDuration;
    this.miniWorldMinMovements = builder.miniWorldMinMovements;
    this.miniWorldMinDistance = builder.miniWorldMinDistance;
    this.allowedBrands = Collections.unmodifiableSet(new HashSet<>(builder.allowedBrands));
    this.usernamePatterns = Collections.unmodifiableSet(new HashSet<>(builder.usernamePatterns));
    this.sequentialCharCheck = builder.sequentialCharCheck;
    this.sequentialCharThreshold = builder.sequentialCharThreshold;
    this.randomDistributionCheck = builder.randomDistributionCheck;
    this.rateLimitWindowMillis = builder.rateLimitWindowMillis;
    this.rateLimitThreshold = builder.rateLimitThreshold;
    this.excludedIps = Collections.unmodifiableSet(new HashSet<>(builder.excludedIps));
    this.minLatencyThreshold = builder.minLatencyThreshold;
    this.maxLatencyThreshold = builder.maxLatencyThreshold;
    this.cleanupThresholdMinutes = builder.cleanupThresholdMinutes;
  }
  
  public boolean isEnabled() {
    return enabled;
  }
  
  public boolean isKickEnabled() {
    return kickEnabled;
  }
  
  public boolean isDebugMode() {
    return debugMode;
  }
  
  public int getKickThreshold() {
    return kickThreshold;
  }
  
  public String getKickMessage() {
    return kickMessage;
  }
  
  public boolean isCheckOnlyFirstJoin() {
    return checkOnlyFirstJoin;
  }
  
  public int getVerificationTimeout() {
    return verificationTimeout;
  }
  
  public boolean isGravityCheckEnabled() {
    return gravityCheckEnabled;
  }
  
  public boolean isHitboxCheckEnabled() {
    return hitboxCheckEnabled;
  }
  
  public boolean isYawCheckEnabled() {
    return yawCheckEnabled;
  }
  
  public boolean isClientBrandCheckEnabled() {
    return clientBrandCheckEnabled;
  }
  
  public boolean isMiniWorldCheckEnabled() {
    return miniWorldCheckEnabled;
  }
  
  public int getMiniWorldDuration() {
    return miniWorldDuration;
  }
  
  public int getMiniWorldMinMovements() {
    return miniWorldMinMovements;
  }
  
  public double getMiniWorldMinDistance() {
    return miniWorldMinDistance;
  }
  
  /**
   * Gets whether connection rate limiting is enabled.
   *
   * @return whether connection rate limiting is enabled
   */
  public boolean isConnectionRateLimitEnabled() {
    return connectionRateLimitEnabled;
  }

  /**
   * Gets the maximum number of connections allowed in the rate window.
   *
   * @return the connection rate limit
   */
  public int getConnectionRateLimit() {
    return connectionRateLimit;
  }

  /**
   * Gets the time window for connection rate limiting in milliseconds.
   *
   * @return the connection rate window in milliseconds
   */
  public long getConnectionRateWindowMs() {
    return connectionRateWindowMs;
  }

  /**
   * Gets the duration for throttling in milliseconds.
   *
   * @return the throttle duration in milliseconds
   */
  public long getThrottleDurationMs() {
    return throttleDurationMs;
  }

  /**
   * Gets whether username pattern checking is enabled.
   *
   * @return whether username pattern checking is enabled
   */
  public boolean isUsernamePatternCheckEnabled() {
    return usernamePatternCheckEnabled;
  }

  /**
   * Gets the threshold for username pattern detection.
   *
   * @return the username pattern threshold
   */
  public int getUsernamePatternThreshold() {
    return usernamePatternThreshold;
  }

  /**
   * Gets whether latency checking is enabled.
   *
   * @return whether latency checking is enabled
   */
  public boolean isLatencyCheckEnabled() {
    return latencyCheckEnabled;
  }

  /**
   * Gets the maximum allowed latency in milliseconds.
   *
   * @return the maximum latency in milliseconds
   */
  public long getMaxLatencyMs() {
    return maxLatencyMs;
  }

  /**
   * Gets whether DNS checking is enabled.
   *
   * @return whether DNS checking is enabled
   */
  public boolean isDnsCheckEnabled() {
    return dnsCheckEnabled;
  }

  /**
   * Gets whether direct IP connections are allowed.
   *
   * @return whether direct IP connections are allowed
   */
  public boolean isAllowDirectIpConnections() {
    return allowDirectIpConnections;
  }

  /**
   * Gets the set of allowed domains.
   *
   * @return the allowed domains
   */
  public Set<String> getAllowedDomains() {
    return allowedDomains;
  }
  
  public Set<String> getAllowedBrands() {
    return allowedBrands;
  }
  
  /**
   * Returns whether players should be kicked on check failures.
   *
   * @return true if players should be kicked
   */
  public boolean isKickOnFailure() {
    return kickEnabled;
  }
  
  /**
   * Gets the username patterns to check against.
   *
   * @return the set of username patterns (regex)
   */
  public Set<String> getUsernamePatterns() {
    return usernamePatterns;
  }
  
  /**
   * Gets whether to check for sequential characters in usernames.
   *
   * @return whether sequential char check is enabled
   */
  public boolean isSequentialCharCheck() {
    return sequentialCharCheck;
  }
  
  /**
   * Gets the threshold for sequential characters in usernames.
   *
   * @return the sequential character threshold
   */
  public int getSequentialCharThreshold() {
    return sequentialCharThreshold;
  }
  
  /**
   * Gets whether to check for random character distribution in usernames.
   *
   * @return whether random distribution check is enabled
   */
  public boolean isRandomDistributionCheck() {
    return randomDistributionCheck;
  }
  
  /**
   * Gets the time window for connection rate limiting in milliseconds.
   *
   * @return the rate limit window in milliseconds
   */
  public long getRateLimitWindowMillis() {
    return rateLimitWindowMillis;
  }
  
  /**
   * Gets the threshold for connection rate limiting.
   *
   * @return the rate limit threshold
   */
  public int getRateLimitThreshold() {
    return rateLimitThreshold;
  }
  
  /**
   * Gets the set of IPs excluded from checks.
   *
   * @return the set of excluded IPs
   */
  public Set<String> getExcludedIps() {
    return excludedIps;
  }
  
  /**
   * Checks if an IP is excluded from anti-bot checks.
   *
   * @param ip the IP to check
   * @return true if the IP is excluded
   */
  public boolean isExcluded(String ip) {
    return excludedIps.contains(ip);
  }
  
  /**
   * Gets the minimum latency threshold in milliseconds.
   *
   * @return the minimum latency threshold
   */
  public long getMinLatencyThreshold() {
    return minLatencyThreshold;
  }
  
  /**
   * Gets the maximum latency threshold in milliseconds.
   *
   * @return the maximum latency threshold
   */
  public long getMaxLatencyThreshold() {
    return maxLatencyThreshold;
  }
  
  /**
   * Gets the cleanup threshold in minutes.
   *
   * @return the cleanup threshold in minutes
   */
  public int getCleanupThresholdMinutes() {
    return cleanupThresholdMinutes;
  }
  
  /**
   * Check if rate limiting is enabled.
   *
   * @return true if rate limiting is enabled, false otherwise
   */
  public boolean isRateLimitEnabled() {
    return connectionRateLimitEnabled;
  }
  
  /**
   * Check if username pattern checking is enabled.
   *
   * @return true if username pattern checking is enabled, false otherwise
   */
  public boolean isPatternCheckEnabled() {
    return usernamePatternCheckEnabled;
  }

  /**
   * Creates a new builder for AntiBotConfig.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }
  
  /**
   * Builder for AntiBotConfig.
   */
  public static class Builder {
    private boolean enabled = true;
    private boolean kickEnabled = true;
    private boolean debugMode = false;
    private int kickThreshold = 5;
    private String kickMessage = "§cYou have been kicked by AntiBot protection";
    private boolean checkOnlyFirstJoin = true;
    private int verificationTimeout = 30;
    
    private boolean gravityCheckEnabled = true;
    private boolean hitboxCheckEnabled = true;
    private boolean yawCheckEnabled = true;
    private boolean clientBrandCheckEnabled = true;
    
    // Mini-world check configuration with defaults
    private boolean miniWorldCheckEnabled = true;
    private int miniWorldDuration = 15;
    private int miniWorldMinMovements = 5;
    private double miniWorldMinDistance = 3.0;
    
    // Connection rate limiting
    private boolean connectionRateLimitEnabled = true;
    private int connectionRateLimit = 100;
    private long connectionRateWindowMs = 60000;
    private long throttleDurationMs = 2000;
    
    // Username pattern check
    private boolean usernamePatternCheckEnabled = true;
    private int usernamePatternThreshold = 3;
    
    // Latency check
    private boolean latencyCheckEnabled = true;
    private long maxLatencyMs = 1000;
    
    // DNS and IP check
    private boolean dnsCheckEnabled = true;
    private boolean allowDirectIpConnections = false;
    private Set<String> allowedDomains = new HashSet<>();
    
    private Set<String> allowedBrands = new HashSet<>();
    
    // Username pattern fields
    private Set<String> usernamePatterns = new HashSet<>();
    private boolean sequentialCharCheck = true;
    private int sequentialCharThreshold = 4;
    private boolean randomDistributionCheck = true;
    
    // Additional rate limiting fields
    private long rateLimitWindowMillis = 60000; // 1 minute
    private int rateLimitThreshold = 10; // 10 connections per minute
    
    // DNS check fields 
    private Set<String> excludedIps = new HashSet<>();
    
    // Latency check additional fields
    private long minLatencyThreshold = 10; // 10ms
    private long maxLatencyThreshold = 1000; // 1000ms
    
    // Cleanup settings
    private int cleanupThresholdMinutes = 10;

    /**
     * Sets whether the AntiBot system is enabled.
     *
     * @param enabled whether the system is enabled
     * @return this builder
     */
    public Builder enabled(boolean enabled) {
      this.enabled = enabled;
      return this;
    }
    
    /**
     * Sets whether to kick players that fail too many checks.
     *
     * @param kickEnabled whether to kick players
     * @return this builder
     */
    public Builder kickEnabled(boolean kickEnabled) {
      this.kickEnabled = kickEnabled;
      return this;
    }
    
    /**
     * Sets the threshold for failed checks before taking action.
     *
     * @param kickThreshold the threshold
     * @return this builder
     */
    public Builder kickThreshold(int kickThreshold) {
      this.kickThreshold = kickThreshold;
      return this;
    }
    
    /**
     * Sets the kick message to display to players.
     *
     * @param kickMessage the kick message
     * @return this builder
     */
    public Builder kickMessage(String kickMessage) {
      this.kickMessage = kickMessage;
      return this;
    }
    
    /**
     * Sets whether to check players only on their first join.
     *
     * @param checkOnlyFirstJoin whether to check players only on first join
     * @return this builder
     */
    public Builder checkOnlyFirstJoin(boolean checkOnlyFirstJoin) {
      this.checkOnlyFirstJoin = checkOnlyFirstJoin;
      return this;
    }
    
    /**
     * Sets the timeout in seconds for player verification.
     *
     * @param verificationTimeout the verification timeout in seconds
     * @return this builder
     */
    public Builder verificationTimeout(int verificationTimeout) {
      this.verificationTimeout = verificationTimeout;
      return this;
    }
    
    /**
     * Sets whether gravity/physics checks are enabled.
     *
     * @param enabled whether the check is enabled
     * @return this builder
     */
    public Builder gravityCheckEnabled(boolean enabled) {
      this.gravityCheckEnabled = enabled;
      return this;
    }
    
    /**
     * Sets whether hitbox interaction checks are enabled.
     *
     * @param enabled whether the check is enabled
     * @return this builder
     */
    public Builder hitboxCheckEnabled(boolean enabled) {
      this.hitboxCheckEnabled = enabled;
      return this;
    }
    
    /**
     * Sets whether yaw/rotation checks are enabled.
     *
     * @param enabled whether the check is enabled
     * @return this builder
     */
    public Builder yawCheckEnabled(boolean enabled) {
      this.yawCheckEnabled = enabled;
      return this;
    }
    
    /**
     * Sets whether client brand checks are enabled.
     *
     * @param enabled whether the check is enabled
     * @return this builder
     */
    public Builder clientBrandCheckEnabled(boolean enabled) {
      this.clientBrandCheckEnabled = enabled;
      return this;
    }
    
    /**
     * Sets whether mini-world environment checks are enabled.
     *
     * @param enabled whether the check is enabled
     * @return this builder
     */
    public Builder miniWorldCheckEnabled(boolean enabled) {
      this.miniWorldCheckEnabled = enabled;
      return this;
    }
    
    /**
     * Sets the duration for the mini-world environment check.
     *
     * @param duration the duration in seconds
     * @return this builder
     */
    public Builder miniWorldDuration(int duration) {
      this.miniWorldDuration = duration;
      return this;
    }
    
    /**
     * Sets the minimum number of movements required in the mini-world.
     *
     * @param minMovements the minimum number of movements
     * @return this builder
     */
    public Builder miniWorldMinMovements(int minMovements) {
      this.miniWorldMinMovements = minMovements;
      return this;
    }
    
    /**
     * Sets the minimum distance for movement in the mini-world.
     *
     * @param minDistance the minimum distance in blocks
     * @return this builder
     */
    public Builder miniWorldMinDistance(double minDistance) {
      this.miniWorldMinDistance = minDistance;
      return this;
    }
    
    /**
     * Sets whether connection rate limiting is enabled.
     *
     * @param enabled whether connection rate limiting is enabled
     * @return this builder
     */
    public Builder connectionRateLimitEnabled(boolean enabled) {
      this.connectionRateLimitEnabled = enabled;
      return this;
    }
    
    /**
     * Sets the connection rate limit.
     *
     * @param limit the maximum number of connections allowed in the rate window
     * @return this builder
     */
    public Builder connectionRateLimit(int limit) {
      this.connectionRateLimit = limit;
      return this;
    }
    
    /**
     * Sets the connection rate window in milliseconds.
     *
     * @param windowMs the time window for connection rate limiting in milliseconds
     * @return this builder
     */
    public Builder connectionRateWindowMs(long windowMs) {
      this.connectionRateWindowMs = windowMs;
      return this;
    }
    
    /**
     * Sets the throttle duration in milliseconds.
     *
     * @param durationMs the duration for throttling in milliseconds
     * @return this builder
     */
    public Builder throttleDurationMs(long durationMs) {
      this.throttleDurationMs = durationMs;
      return this;
    }
    
    /**
     * Sets whether to check player usernames against patterns.
     *
     * @param enabled whether the check is enabled
     * @return this builder
     */
    public Builder usernamePatternCheckEnabled(boolean enabled) {
      this.usernamePatternCheckEnabled = enabled;
      return this;
    }
    
    /**
     * Sets the threshold for username pattern checks.
     *
     * @param threshold the threshold
     * @return this builder
     */
    public Builder usernamePatternThreshold(int threshold) {
      this.usernamePatternThreshold = threshold;
      return this;
    }
    
    /**
     * Sets whether to check player latency.
     *
     * @param enabled whether the check is enabled
     * @return this builder
     */
    public Builder latencyCheckEnabled(boolean enabled) {
      this.latencyCheckEnabled = enabled;
      return this;
    }
    
    /**
     * Sets the maximum allowed latency.
     *
     * @param maxLatencyMs the maximum latency in milliseconds
     * @return this builder
     */
    public Builder maxLatencyMs(long maxLatencyMs) {
      this.maxLatencyMs = maxLatencyMs;
      return this;
    }
    
    /**
     * Sets whether to perform DNS and IP checks.
     *
     * @param enabled whether the check is enabled
     * @return this builder
     */
    public Builder dnsCheckEnabled(boolean enabled) {
      this.dnsCheckEnabled = enabled;
      return this;
    }
    
    /**
     * Sets whether to allow direct IP connections.
     *
     * @param allowed whether to allow direct IP connections
     * @return this builder
     */
    public Builder allowDirectIpConnections(boolean allowed) {
      this.allowDirectIpConnections = allowed;
      return this;
    }
    
    /**
     * Sets the allowed domains.
     *
     * @param domains the allowed domains
     * @return this builder
     */
    public Builder allowedDomains(Set<String> domains) {
      this.allowedDomains = domains;
      return this;
    }
    
    /**
     * Adds an allowed domain for connections.
     *
     * @param domain the allowed domain
     * @return this builder
     */
    public Builder addAllowedDomain(String domain) {
      this.allowedDomains.add(domain);
      return this;
    }
    
    /**
     * Sets the allowed client brands.
     *
     * @param brands the allowed client brands
     * @return this builder
     */
    public Builder allowedBrands(Set<String> brands) {
      this.allowedBrands = new HashSet<>(brands);
      return this;
    }
    
    /**
     * Adds an allowed client brand.
     *
     * @param brand the allowed client brand
     * @return this builder
     */
    public Builder addAllowedBrand(String brand) {
      this.allowedBrands.add(brand);
      return this;
    }
    
    /**
     * Sets the username patterns to check against.
     *
     * @param patterns the patterns to check
     * @return this builder
     */
    public Builder usernamePatterns(Set<String> patterns) {
      this.usernamePatterns = new HashSet<>(patterns);
      return this;
    }
    
    /**
     * Adds a username pattern to check against.
     *
     * @param pattern the pattern to add
     * @return this builder
     */
    public Builder addUsernamePattern(String pattern) {
      this.usernamePatterns.add(pattern);
      return this;
    }
    
    /**
     * Sets whether to check for sequential characters in usernames.
     *
     * @param enabled whether the check is enabled
     * @return this builder
     */
    public Builder sequentialCharCheck(boolean enabled) {
      this.sequentialCharCheck = enabled;
      return this;
    }
    
    /**
     * Sets the threshold for sequential characters in usernames.
     *
     * @param threshold the threshold
     * @return this builder
     */
    public Builder sequentialCharThreshold(int threshold) {
      this.sequentialCharThreshold = threshold;
      return this;
    }
    
    /**
     * Sets whether to check for random character distribution in usernames.
     *
     * @param enabled whether the check is enabled
     * @return this builder
     */
    public Builder randomDistributionCheck(boolean enabled) {
      this.randomDistributionCheck = enabled;
      return this;
    }
    
    /**
     * Sets the time window for connection rate limiting in milliseconds.
     *
     * @param windowMillis the window in milliseconds
     * @return this builder
     */
    public Builder rateLimitWindowMillis(long windowMillis) {
      this.rateLimitWindowMillis = windowMillis;
      return this;
    }
    
    /**
     * Sets the threshold for connection rate limiting.
     *
     * @param threshold the threshold
     * @return this builder
     */
    public Builder rateLimitThreshold(int threshold) {
      this.rateLimitThreshold = threshold;
      return this;
    }
    
    /**
     * Sets the IPs excluded from checks.
     *
     * @param ips the excluded IPs
     * @return this builder
     */
    public Builder excludedIps(Set<String> ips) {
      this.excludedIps = new HashSet<>(ips);
      return this;
    }
    
    /**
     * Adds an IP to the exclusion list.
     *
     * @param ip the IP to exclude
     * @return this builder
     */
    public Builder addExcludedIp(String ip) {
      this.excludedIps.add(ip);
      return this;
    }
    
    /**
     * Sets the minimum latency threshold in milliseconds.
     *
     * @param threshold the threshold
     * @return this builder
     */
    public Builder minLatencyThreshold(long threshold) {
      this.minLatencyThreshold = threshold;
      return this;
    }
    
    /**
     * Sets the maximum latency threshold in milliseconds.
     *
     * @param threshold the threshold
     * @return this builder
     */
    public Builder maxLatencyThreshold(long threshold) {
      this.maxLatencyThreshold = threshold;
      return this;
    }
    
    /**
     * Sets the cleanup threshold in minutes.
     *
     * @param minutes the cleanup threshold in minutes
     * @return this builder
     */
    public Builder cleanupThresholdMinutes(int minutes) {
      this.cleanupThresholdMinutes = minutes;
      return this;
    }
    
    /**
     * Builds the AntiBotConfig.
     *
     * @return the built config
     */
    public AntiBotConfig build() {
      return new AntiBotConfig(this);
    }
  }
}
