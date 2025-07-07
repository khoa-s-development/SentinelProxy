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

import io.netty.channel.ChannelPipeline;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.HashSet;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.velocitypowered.proxy.VelocityServer;

/**
 * Central manager for all security-related modules.
 * Manages configuration, startup, and coordination of DDoS protection modules.
 */
public class SecurityManager {

  private static final Logger logger = LoggerFactory.getLogger(SecurityManager.class);
  
  private final VelocityServer server;
  private final boolean securityEnabled;
  
  // Protection modules
  private final Layer4Handler layer4Handler;
  private final Layer7Handler layer7Handler;
  private final PacketFilter packetFilter;
  private final AntiBot antiBot;
  
  // Maintenance tasks
  private ScheduledFuture<?> maintenanceTask;
  private ScheduledFuture<?> statusReportTask;

  /**
   * Creates a new security manager with the specified configuration.
   *
   * @param server The Velocity server instance
   * @param securityEnabled Whether security modules are enabled
   * @param layer4Enabled Whether layer 4 protection is enabled
   * @param layer7Enabled Whether layer 7 protection is enabled
   * @param packetFilterEnabled Whether packet filtering is enabled
   * @param antiBotEnabled Whether AntiBot protection is enabled
   */
  public SecurityManager(VelocityServer server, boolean securityEnabled,
                        boolean layer4Enabled, boolean layer7Enabled, 
                        boolean packetFilterEnabled, boolean antiBotEnabled) {
    this.server = server;
    this.securityEnabled = securityEnabled;

    // Initialize protection modules
    if (securityEnabled && layer4Enabled) {
      AntiDdosConfig layer4Config = createLayer4Config();
      this.layer4Handler = new Layer4Handler(layer4Config);
    } else {
      this.layer4Handler = null;
    }
    
    if (securityEnabled && layer7Enabled) {
      Layer7Config layer7Config = createLayer7Config();
      this.layer7Handler = new Layer7Handler(server, layer7Config);
    } else {
      this.layer7Handler = null;
    }
    
    if (securityEnabled && packetFilterEnabled) {
      PacketFilterConfig packetFilterConfig = createPacketFilterConfig();
      this.packetFilter = new PacketFilter(packetFilterConfig);
    } else {
      this.packetFilter = null;
    }
    
    if (securityEnabled && antiBotEnabled) {
      AntiBotConfig antiBotConfig = createAntiBotConfig();
      this.antiBot = server.getAntiBot();
      this.antiBot.configure(antiBotConfig);
    } else {
      this.antiBot = null;
    }

    logger.info("SecurityManager initialized. Security enabled: {}", securityEnabled);
  }

  /**
   * Start the security manager and its maintenance tasks.
   * 
   * @param executorService The scheduler to use for periodic tasks
   */
  public void start(ScheduledExecutorService executorService) {
    if (!securityEnabled) {
      logger.info("Security modules are disabled");
      return;
    }

    logger.info("Starting security modules and maintenance tasks");

    // Schedule maintenance tasks
    maintenanceTask = executorService.scheduleAtFixedRate(
        this::performMaintenance, 1, 1, TimeUnit.MINUTES);
        
    statusReportTask = executorService.scheduleAtFixedRate(
        this::reportStatus, 5, 15, TimeUnit.MINUTES);
        
    logger.info("Security modules started successfully");
  }

  /**
   * Stop all security modules and tasks.
   */
  public void stop() {
    if (!securityEnabled) {
      return;
    }

    logger.info("Stopping security modules and tasks");
    
    if (maintenanceTask != null) {
      maintenanceTask.cancel(false);
    }
    
    if (statusReportTask != null) {
      statusReportTask.cancel(false);
    }
    
    logger.info("Security modules stopped");
  }

  /**
   * Configure the pipeline with security handlers.
   *
   * @param pipeline The Netty pipeline to configure
   */
  public void configureSecurityPipeline(ChannelPipeline pipeline) {
    if (!securityEnabled) {
      return;
    }

    if (layer4Handler != null) {
      pipeline.addLast("layer4-handler", layer4Handler);
      logger.debug("Added Layer4Handler to pipeline");
    }
    
    if (packetFilter != null) {
      pipeline.addLast("packet-filter", packetFilter);
      logger.debug("Added PacketFilter to pipeline");
    }
    
    if (layer7Handler != null) {
      pipeline.addLast("layer7-handler", layer7Handler);
      logger.debug("Added Layer7Handler to pipeline");
    }
  }

  /**
   * Perform periodic maintenance on all security modules.
   */
  private void performMaintenance() {
    try {
      if (layer4Handler != null) {
        layer4Handler.cleanupBlockedIps();
      }
      
      if (layer7Handler != null) {
        layer7Handler.cleanup();
      }
      
      if (packetFilter != null) {
        packetFilter.cleanup();
      }
      
      if (antiBot != null) {
        antiBot.cleanup();
      }
    } catch (Exception e) {
      logger.error("Error during security maintenance", e);
    }
  }

  /**
   * Report status of all security modules.
   */
  private void reportStatus() {
    try {
      logger.info("=== Security Status Report ===");
      
      if (layer4Handler != null) {
        layer4Handler.reportStatus();
      }
      
      if (layer7Handler != null) {
        layer7Handler.reportStatus();
      }
      
      if (packetFilter != null) {
        packetFilter.reportStatus();
      }
      
      if (antiBot != null) {
        antiBot.reportStatus();
      }
      
      logger.info("============================");
    } catch (Exception e) {
      logger.error("Error during security status reporting", e);
    }
  }

  /**
   * Create Layer 4 configuration from server settings.
   */
  private AntiDdosConfig createLayer4Config() {
    // In a real implementation, this would pull values from the Velocity configuration
    // For now we'll use defaults
    AntiDdosConfig config = new AntiDdosConfig();
    
    // TODO: Pull these values from Velocity config when available
    return config;
  }

  /**
   * Create Layer 7 configuration from server settings.
   */
  private Layer7Config createLayer7Config() {
    // In a real implementation, this would pull values from the Velocity configuration
    // For now we'll use the builder pattern with defaults
    Layer7Config config = Layer7Config.builder()
        .maxLoginAttemptsPerIp(20)
        .maxPacketTypePerSecond(100)
        .maxServerListPingsPerIp(3)
        .blockDurationMs(TimeUnit.MINUTES.toMillis(5))
        .detectProtocolViolations(true)
        .trackPacketPatterns(true)
        // Anti-Bot settings are now handled by the dedicated AntiBot class
        .build();
    
    // TODO: Pull these values from Velocity config when available
    return config;
  }

  /**
   * Create packet filter configuration from server settings.
   */
  private PacketFilterConfig createPacketFilterConfig() {
    // In a real implementation, this would pull values from the Velocity configuration
    // For now we'll use defaults
    PacketFilterConfig config = new PacketFilterConfig();
    
    // TODO: Pull these values from Velocity config when available
    return config;
  }
  
  /**
   * Create AntiBot configuration from server settings.
   */
  private AntiBotConfig createAntiBotConfig() {
    // In a real implementation, this would pull values from the Velocity configuration
    // For now we'll use the builder pattern with defaults
    
    // Create a set of allowed client brands
    Set<String> allowedBrandSet = new HashSet<>();
    allowedBrandSet.add("vanilla");
    allowedBrandSet.add("fabric");
    allowedBrandSet.add("forge");
    allowedBrandSet.add("lunar");
    allowedBrandSet.add("badlion");
    allowedBrandSet.add("feather");
    
    AntiBotConfig config = AntiBotConfig.builder()
        .enabled(true)
        .checkOnlyFirstJoin(true)
        .gravityCheckEnabled(true)
        .hitboxCheckEnabled(true)
        .yawCheckEnabled(true)
        .clientBrandCheckEnabled(true)
        .allowedBrands(allowedBrandSet)
        .kickMessage("You failed the automated bot check. Please reconnect.")
        .kickThreshold(5)
        .build();
    
    // TODO: Pull these values from Velocity config when available
    return config;
  }
}
