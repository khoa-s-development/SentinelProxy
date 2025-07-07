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

import com.moandjiezana.toml.Toml;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.HashSet;
import java.util.Set;

/**
 * Helper class to parse security configuration from TOML.
 */
public class SecurityConfigParser {

  private static final Logger logger = LoggerFactory.getLogger(SecurityConfigParser.class);

  /**
   * Create AntiDdosConfig (Layer4) from TOML.
   *
   * @param toml The TOML configuration
   * @return A new AntiDdosConfig
   */
  public static AntiDdosConfig parseLayer4Config(Toml toml) {
    try {
      Toml securitySection = toml.getTable("security");
      if (securitySection == null) {
        logger.warn("No security section found in configuration, using defaults");
        return new AntiDdosConfig();
      }

      Toml layer4Section = securitySection.getTable("layer4");
      if (layer4Section == null) {
        logger.warn("No layer4 section found in configuration, using defaults");
        return new AntiDdosConfig();
      }

      int maxConnectionsPerIp = layer4Section.getLong("max-connections-per-ip", 5L).intValue();
      int maxPacketsPerSecond = layer4Section.getLong("max-packets-per-second", 100L).intValue();
      long blockDurationMs = layer4Section.getLong("block-duration-ms", 300000L);
      long rateLimitWindowMs = layer4Section.getLong("rate-limit-window-ms", 1000L);

      AntiDdosConfig config = new AntiDdosConfig(
          maxConnectionsPerIp,
          maxPacketsPerSecond,
          rateLimitWindowMs,
          blockDurationMs);

      logger.debug("Parsed Layer4 config: maxConnections={}, maxPackets={}, blockDuration={}ms",
          maxConnectionsPerIp, maxPacketsPerSecond, blockDurationMs);
      return config;
    } catch (Exception e) {
      logger.error("Error parsing Layer4 configuration", e);
      return new AntiDdosConfig();
    }
  }

  /**
   * Create Layer7Config from TOML.
   *
   * @param toml The TOML configuration
   * @return A new Layer7Config
   */
  public static Layer7Config parseLayer7Config(Toml toml) {
    try {
      Toml securitySection = toml.getTable("security");
      if (securitySection == null) {
        logger.warn("No security section found in configuration, using defaults");
        return new Layer7Config();
      }

      Toml layer7Section = securitySection.getTable("layer7");
      if (layer7Section == null) {
        logger.warn("No layer7 section found in configuration, using defaults");
        return new Layer7Config();
      }

      int maxLoginAttempts = layer7Section.getLong("max-login-attempts", 20L).intValue();
      int maxServerListPings = layer7Section.getLong("max-server-list-pings", 3L).intValue();
      int maxPacketTypePerSecond = layer7Section.getLong("max-packet-type-per-second", 100L).intValue();
      long blockDurationMs = layer7Section.getLong("block-duration-ms", 300000L);
      boolean detectProtocolViolations = layer7Section.getBoolean("detect-protocol-violations", true);
      boolean trackPacketPatterns = layer7Section.getBoolean("track-packet-patterns", true);

      return Layer7Config.builder()
          .maxLoginAttemptsPerIp(maxLoginAttempts)
          .maxPacketTypePerSecond(maxPacketTypePerSecond)
          .maxServerListPingsPerIp(maxServerListPings)
          .blockDurationMs(blockDurationMs)
          .detectProtocolViolations(detectProtocolViolations)
          .trackPacketPatterns(trackPacketPatterns)
          .build();
    } catch (Exception e) {
      logger.error("Error parsing Layer7 configuration", e);
      return new Layer7Config();
    }
  }

  /**
   * Create PacketFilterConfig from TOML.
   *
   * @param toml The TOML configuration
   * @return A new PacketFilterConfig
   */
  public static PacketFilterConfig parsePacketFilterConfig(Toml toml) {
    try {
      Toml securitySection = toml.getTable("security");
      if (securitySection == null) {
        logger.warn("No security section found in configuration, using defaults");
        return new PacketFilterConfig();
      }

      Toml filterSection = securitySection.getTable("packet-filter");
      if (filterSection == null) {
        logger.warn("No packet-filter section found in configuration, using defaults");
        return new PacketFilterConfig();
      }

      int maxPacketSize = filterSection.getLong("max-packet-size", 32768L).intValue();
      boolean blockHarmfulPatterns = filterSection.getBoolean("block-harmful-patterns", true);
      boolean blockRepeatedPackets = filterSection.getBoolean("block-repeated-packets", true);
      String packetWhitelist = filterSection.getString("packet-whitelist", "Handshake,ServerPing,LoginStart");

      return new PacketFilterConfig(
          maxPacketSize,
          blockHarmfulPatterns,
          blockRepeatedPackets,
          packetWhitelist
      );
    } catch (Exception e) {
      logger.error("Error parsing packet filter configuration", e);
      return new PacketFilterConfig();
    }
  }

  /**
   * Check if security features are enabled.
   *
   * @param toml The TOML configuration
   * @return True if security features should be enabled
   */
  public static boolean isSecurityEnabled(Toml toml) {
    try {
      Toml securitySection = toml.getTable("security");
      return securitySection != null && securitySection.getBoolean("enable-ddos-protection", true);
    } catch (Exception e) {
      logger.error("Error checking if security is enabled", e);
      return true; // Default to enabled for safety
    }
  }

  /**
   * Check if Layer4 protection is enabled.
   *
   * @param toml The TOML configuration
   * @return True if Layer4 protection should be enabled
   */
  public static boolean isLayer4Enabled(Toml toml) {
    try {
      Toml securitySection = toml.getTable("security");
      if (securitySection == null) {
        return false;
      }
      
      Toml layer4Section = securitySection.getTable("layer4");
      return layer4Section != null && layer4Section.getBoolean("enabled", true);
    } catch (Exception e) {
      logger.error("Error checking if Layer4 is enabled", e);
      return true; // Default to enabled for safety
    }
  }

  /**
   * Check if Layer7 protection is enabled.
   *
   * @param toml The TOML configuration
   * @return True if Layer7 protection should be enabled
   */
  public static boolean isLayer7Enabled(Toml toml) {
    try {
      Toml securitySection = toml.getTable("security");
      if (securitySection == null) {
        return false;
      }
      
      Toml layer7Section = securitySection.getTable("layer7");
      return layer7Section != null && layer7Section.getBoolean("enabled", true);
    } catch (Exception e) {
      logger.error("Error checking if Layer7 is enabled", e);
      return true; // Default to enabled for safety
    }
  }

  /**
   * Check if packet filtering is enabled.
   *
   * @param toml The TOML configuration
   * @return True if packet filtering should be enabled
   */
  public static boolean isPacketFilterEnabled(Toml toml) {
    try {
      Toml securitySection = toml.getTable("security");
      if (securitySection == null) {
        return false;
      }
      
      Toml filterSection = securitySection.getTable("packet-filter");
      return filterSection != null && filterSection.getBoolean("enabled", true);
    } catch (Exception e) {
      logger.error("Error checking if packet filter is enabled", e);
      return true; // Default to enabled for safety
    }
  }
  
  /**
   * Check if AntiBot protection is enabled.
   *
   * @param toml The TOML configuration
   * @return True if AntiBot protection should be enabled
   */
  public static boolean isAntiBotEnabled(Toml toml) {
    try {
      Toml securitySection = toml.getTable("security");
      if (securitySection == null) {
        return false;
      }
      
      Toml antiBotSection = securitySection.getTable("anti-bot");
      return antiBotSection != null && antiBotSection.getBoolean("enabled", true);
    } catch (Exception e) {
      logger.error("Error checking if AntiBot is enabled", e);
      return true; // Default to enabled for safety
    }
  }
  
  /**
   * Create AntiBotConfig from TOML.
   *
   * @param toml The TOML configuration
   * @return A new AntiBotConfig
   */
  public static AntiBotConfig parseAntiBotConfig(Toml toml) {
    try {
      Toml securitySection = toml.getTable("security");
      if (securitySection == null) {
        logger.warn("No security section found in configuration, using defaults for AntiBot");
        return AntiBotConfig.builder().build();
      }

      Toml antiBotSection = securitySection.getTable("anti-bot");
      if (antiBotSection == null) {
        logger.warn("No anti-bot section found in configuration, using defaults");
        return AntiBotConfig.builder().build();
      }

      boolean enabled = antiBotSection.getBoolean("enabled", true);
      boolean checkOnlyFirstJoin = antiBotSection.getBoolean("check-only-first-join", true);
      int verificationTimeout = antiBotSection.getLong("verification-timeout", 30L).intValue();
      boolean gravityChecksEnabled = antiBotSection.getBoolean("enable-gravity-checks", true);
      boolean hitboxChecksEnabled = antiBotSection.getBoolean("enable-hitbox-checks", true);
      boolean yawChecksEnabled = antiBotSection.getBoolean("enable-rotation-checks", true);
      boolean clientBrandChecksEnabled = antiBotSection.getBoolean("enable-client-brand-checks", true);
      String allowedBrandsStr = antiBotSection.getString("allowed-client-brands", "vanilla,fabric,forge,lunar,badlion,feather");
      String kickMessage = antiBotSection.getString("kick-message", "You failed the automated bot check. Please reconnect.");
      
      // Mini-world check configuration
      boolean miniWorldCheckEnabled = antiBotSection.getBoolean("enable-mini-world-check", true);
      int miniWorldDuration = antiBotSection.getLong("mini-world-duration", 15L).intValue();
      int miniWorldMinMovements = antiBotSection.getLong("mini-world-min-movements", 5L).intValue();
      double miniWorldMinDistance = antiBotSection.getDouble("mini-world-min-distance", 3.0);
      
      // New settings for advanced anti-bot features
      
      // Connection rate limiting
      boolean rateLimitEnabled = antiBotSection.getBoolean("enable-rate-limit", true);
      int rateLimitThreshold = antiBotSection.getLong("rate-limit-threshold", 10L).intValue();
      long rateLimitWindowMillis = antiBotSection.getLong("rate-limit-window-ms", 60000L);
      
      // Username pattern detection
      boolean patternCheckEnabled = antiBotSection.getBoolean("enable-pattern-check", true);
      String patternsStr = antiBotSection.getString("username-patterns", "bot[0-9]+,player[0-9]{5},user[0-9]+");
      boolean sequentialCharCheck = antiBotSection.getBoolean("check-sequential-chars", true);
      int sequentialCharThreshold = antiBotSection.getLong("sequential-char-threshold", 4L).intValue();
      boolean randomDistributionCheck = antiBotSection.getBoolean("check-random-distribution", true);
      
      // DNS/IP Checks
      boolean dnsCheckEnabled = antiBotSection.getBoolean("enable-dns-check", true);
      boolean allowDirectIpConnections = antiBotSection.getBoolean("allow-direct-ip-connections", false);
      String allowedDomainsStr = antiBotSection.getString("allowed-domains", "");
      String excludedIpsStr = antiBotSection.getString("excluded-ips", "127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12");
      
      // Latency check
      boolean latencyCheckEnabled = antiBotSection.getBoolean("enable-latency-check", true);
      long minLatencyThreshold = antiBotSection.getLong("min-latency-ms", 10L);
      long maxLatencyThreshold = antiBotSection.getLong("max-latency-ms", 1000L);
      
      // Cleanup settings
      int cleanupThresholdMinutes = antiBotSection.getLong("cleanup-threshold-minutes", 10L).intValue();
      
      // Parse allowed brands
      Set<String> allowedBrands = new HashSet<>();
      for (String brand : allowedBrandsStr.split(",")) {
        allowedBrands.add(brand.trim());
      }
      
      // Parse allowed domains
      Set<String> allowedDomains = new HashSet<>();
      if (!allowedDomainsStr.isEmpty()) {
        for (String domain : allowedDomainsStr.split(",")) {
          allowedDomains.add(domain.trim());
        }
      }
      
      // Parse excluded IPs
      Set<String> excludedIps = new HashSet<>();
      for (String ip : excludedIpsStr.split(",")) {
        excludedIps.add(ip.trim());
      }
      
      // Parse username patterns
      Set<String> patterns = new HashSet<>();
      if (!patternsStr.isEmpty()) {
        for (String pattern : patternsStr.split(",")) {
          patterns.add(pattern.trim());
        }
      }
      
      // Use the static builder method
      AntiBotConfig.Builder builder = AntiBotConfig.builder()
          .enabled(enabled)
          .checkOnlyFirstJoin(checkOnlyFirstJoin)
          .verificationTimeout(verificationTimeout)
          .kickMessage(kickMessage)
          .gravityCheckEnabled(gravityChecksEnabled)
          .hitboxCheckEnabled(hitboxChecksEnabled)
          .yawCheckEnabled(yawChecksEnabled)
          .clientBrandCheckEnabled(clientBrandChecksEnabled)
          .miniWorldCheckEnabled(miniWorldCheckEnabled)
          .miniWorldDuration(miniWorldDuration)
          .miniWorldMinMovements(miniWorldMinMovements)
          .miniWorldMinDistance(miniWorldMinDistance)
          .allowedBrands(allowedBrands)
          // New settings
          .connectionRateLimitEnabled(rateLimitEnabled)
          .rateLimitThreshold(rateLimitThreshold)
          .rateLimitWindowMillis(rateLimitWindowMillis)
          .usernamePatternCheckEnabled(patternCheckEnabled)
          .usernamePatterns(patterns)
          .sequentialCharCheck(sequentialCharCheck)
          .sequentialCharThreshold(sequentialCharThreshold)
          .randomDistributionCheck(randomDistributionCheck)
          .dnsCheckEnabled(dnsCheckEnabled)
          .allowDirectIpConnections(allowDirectIpConnections)
          .allowedDomains(allowedDomains)
          .excludedIps(excludedIps)
          .latencyCheckEnabled(latencyCheckEnabled)
          .minLatencyThreshold(minLatencyThreshold)
          .maxLatencyThreshold(maxLatencyThreshold)
          .cleanupThresholdMinutes(cleanupThresholdMinutes);
      
      // Set kick threshold if present
      if (antiBotSection.contains("kick-threshold")) {
        builder.kickThreshold(antiBotSection.getLong("kick-threshold", 5L).intValue());
      }

      AntiBotConfig config = builder.build();
      
      logger.debug("Parsed AntiBot config: enabled={}, rateLimitEnabled={}, patternCheckEnabled={}, dnsCheckEnabled={}, latencyCheckEnabled={}", 
          enabled, rateLimitEnabled, patternCheckEnabled, dnsCheckEnabled, latencyCheckEnabled);
      
      return config;
    } catch (Exception e) {
      logger.error("Error parsing AntiBot configuration", e);
      return AntiBotConfig.builder().build();
    }
  }
}
