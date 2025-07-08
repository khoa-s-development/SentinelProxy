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

import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.ResultedEvent;
import java.util.concurrent.CompletableFuture;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.player.PlayerChatEvent;
import com.velocitypowered.api.event.connection.PluginMessageEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.plugin.PluginContainer;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.util.Vector3d;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.connection.client.ConnectedPlayer;
import com.velocitypowered.proxy.protocol.packet.PluginMessagePacket;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.Iterator;
import java.util.Optional;
import java.util.UUID;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.LinkedList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Advanced Anti-Bot protection for Minecraft servers.
 * Implements multiple checks to detect and prevent bot attacks:
 * - Gravity and physics checks
 * - Movement pattern analysis
 * - Client brand verification
 * - Hitbox interaction analysis
 * - Yaw/pitch check for suspicious rotations
 */
public class AntiBot {
  
  private static final Logger logger = LoggerFactory.getLogger(AntiBot.class);
  
  /**
   * Logs debug information only if debug mode is enabled.
   * This helps reduce console spam when debug mode is disabled.
   * 
   * @param message the debug message
   * @param args the arguments for the message
   */
  private void debugLog(String message, Object... args) {
    if (config != null && config.isDebugMode()) {
      logger.debug(message, args);
    }
  }
  
  /**
   * Logs info information only if debug mode is enabled, otherwise logs as debug.
   * Use this for information that's useful but might spam the console.
   * 
   * @param message the info message
   * @param args the arguments for the message
   */
  private void infoLog(String message, Object... args) {
    if (config != null && config.isDebugMode()) {
      logger.info(message, args);
    } else {
      logger.debug(message, args);
    }
  }
  
  private final VelocityServer server;
  private AntiBotConfig config;
  
  // Player tracking for bot detection
  private final Map<UUID, PlayerState> playerStates = new ConcurrentHashMap<>();
  private final Map<InetAddress, AtomicInteger> connectionsByIp = new ConcurrentHashMap<>();
  private final Set<UUID> verifiedPlayers = new HashSet<>();
  private final Set<UUID> suspiciousPlayers = new HashSet<>();
  private final Map<UUID, Integer> failedChecks = new ConcurrentHashMap<>();
  
  // Advanced anti-bot features
  private final Map<InetAddress, List<Long>> connectionTimestampsByIp = new ConcurrentHashMap<>();
  private final Map<String, AtomicInteger> connectionsByUsername = new ConcurrentHashMap<>();
  private final Map<InetAddress, Long> latencyByIp = new ConcurrentHashMap<>();
  private final Set<InetAddress> resolvedAddresses = ConcurrentHashMap.newKeySet();
  private final Set<String> usernamePatterns = ConcurrentHashMap.newKeySet();
  private final Set<InetAddress> throttledIps = ConcurrentHashMap.newKeySet();
  private final Map<InetAddress, String> dnsResolveCache = new ConcurrentHashMap<>();
  private final Map<String, Integer> usernamePatternCounts = new ConcurrentHashMap<>();
  
  private boolean enabled = true;
  private int kickThreshold = 5; // Number of failed checks before kicking
  
  // MiniWorld environment check - constants
  private static final int MINIWORLD_CHECK_DURATION_SECONDS = 15;
  private static final int MINIWORLD_MIN_MOVEMENTS = 5;
  private static final double MINIWORLD_MIN_DISTANCE = 3.0;
  
  // Temporary server configuration for mini-world checks
  private static final String MINIWORLD_SERVER_NAME = "antibot-verification";
  private static final String MINIWORLD_FALLBACK_SERVER = "lobby";
  private final Map<UUID, RegisteredServer> originalDestinations = new ConcurrentHashMap<>();
  private final Set<UUID> pendingTransfers = ConcurrentHashMap.newKeySet();
  
  // Map to track players in the mini-world check
  private final Map<UUID, MiniWorldSession> miniWorldSessions = new ConcurrentHashMap<>();
  
  // Virtual verification world (no external server required)
  private final VirtualVerificationWorld virtualWorld;
  
  /**
   * Creates a new AntiBot instance.
   *
   * @param server the Velocity server instance
   * @param config the AntiBot configuration
   */
  public AntiBot(VelocityServer server, AntiBotConfig config) {
    this.server = server;
    this.config = config;
    this.enabled = config.isEnabled();
    this.kickThreshold = config.getKickThreshold();
    
    // Initialize virtual verification world
    this.virtualWorld = new VirtualVerificationWorld(this);
    
    logger.info("AntiBot initialized with {} checks enabled", 
        (config.isGravityCheckEnabled() ? 1 : 0) + 
        (config.isHitboxCheckEnabled() ? 1 : 0) + 
        (config.isYawCheckEnabled() ? 1 : 0) + 
        (config.isClientBrandCheckEnabled() ? 1 : 0));
  }
  
  /**
   * Initialize the scheduler for cleanup tasks.
   * This should be called after the server has registered its plugins.
   */
  public void initializeScheduler() {
    // Scheduler will be initialized later after the plugin is registered
  }
  
  /**
   * Handle player connection event for bot detection.
   *
   * @param event the login event
   */
  // NOTE: This system now uses a built-in virtual verification world that runs within the proxy.
  // No external server configuration is required!

  @Subscribe(order = PostOrder.FIRST)
  public void onPlayerLogin(LoginEvent event) {
    if (!enabled) {
      return;
    }
    Player player = event.getPlayer();
    UUID playerId = player.getUniqueId();
    InetSocketAddress socketAddress = player.getRemoteAddress();
    InetAddress address = socketAddress.getAddress();
    String username = player.getUsername();
    
    // Check if IP is currently throttled
    if (isIpThrottled(address)) {
      logger.warn("Rejected login from throttled IP: {} ({})", address.getHostAddress(), username);
      event.setResult(ResultedEvent.ComponentResult.denied(
          Component.text("Connection throttled due to excessive login attempts")
      ));
      return;
    }
    
    // Check connection rate
    if (!checkConnectionRate(address)) {
      logger.warn("Rejected login due to excessive connection rate: {} ({})", 
          address.getHostAddress(), username);
      event.setResult(ResultedEvent.ComponentResult.denied(
          Component.text("Too many connections too quickly")
      ));
      return;
    }
    
    // Check username pattern
    if (!checkUsernamePattern(username)) {
      logger.warn("Rejected login due to suspicious username pattern: {}", username);
      event.setResult(ResultedEvent.ComponentResult.denied(
          Component.text("Username pattern not allowed")
      ));
      return;
    }
    
    // Check hostname/DNS if available
    Optional<String> virtualHost = player.getVirtualHost().map(InetSocketAddress::getHostName);
    if (virtualHost.isPresent() && !checkDnsResolution(address, virtualHost.get())) {
      logger.warn("Rejected login due to DNS check failure: {} via {}", 
          username, virtualHost.get());
      event.setResult(ResultedEvent.ComponentResult.denied(
          Component.text("Connection not allowed through this domain")
      ));
      return;
    }
    
    // Track new connection
    connectionsByIp.computeIfAbsent(address, k -> new AtomicInteger(0)).incrementAndGet();
    
    // Initialize player state
    playerStates.put(playerId, new PlayerState(playerId, address));
    
    // Enhanced connection logging
    AtomicInteger currentConnections = connectionsByIp.get(address);
    int connectionCount = currentConnections.get();
    
    debugLog("[CONNECTION] Player {} ({}) connected from {}", 
        player.getUsername(), playerId, address.getHostAddress());
    debugLog("[CONNECTION] IP {} now has {} active connections", 
        address.getHostAddress(), connectionCount);
    
    // Log virtual host information
    if (virtualHost.isPresent()) {
      debugLog("[CONNECTION] Player {} connecting via virtual host: {}", 
          username, virtualHost.get());
    }
    
    // Log player state checks
    boolean isVerified = verifiedPlayers.contains(playerId);
    boolean isExempt = config.getExcludedIps().contains(address.getHostAddress());
    boolean shouldVerify = config.isMiniWorldCheckEnabled() && !isVerified && !isExempt;
    
    logger.debug("[CONNECTION] Player {} verification status - Verified: {}, Exempt: {}, Should verify: {}", 
        username, isVerified, isExempt, shouldVerify);
        
    // Determine the initial target server for this player
    Optional<RegisteredServer> initialTargetServer = determineInitialServer(player);
    
    if (initialTargetServer.isPresent()) {
      logger.debug("[CONNECTION] Determined initial target server for {}: {}", 
          username, initialTargetServer.get().getServerInfo().getName());
    } else {
      logger.warn("[CONNECTION] No initial target server found for player {}", username);
    }
    
    // If mini-world check is enabled, reroute to virtual verification world
    if (shouldVerify) {
      logger.info("[VERIFICATION] Player {} requires verification, redirecting to virtual verification world", username);
      
      // Store the original destination for later
      initialTargetServer.ifPresent(server -> {
        originalDestinations.put(playerId, server);
        logger.debug("[VERIFICATION] Stored original destination for {}: {}", 
            username, server.getServerInfo().getName());
      });
      
      // Use the virtual verification world instead of external server
      if (player instanceof ConnectedPlayer) {
        ConnectedPlayer connectedPlayer = (ConnectedPlayer) player;
        
        // Enter the player into the virtual verification world
        boolean enteredVirtualWorld = virtualWorld.enterVerificationWorld(connectedPlayer);
        
        if (enteredVirtualWorld) {
          logger.info("[VERIFICATION] Player {} successfully entered virtual verification world", username);
          
          // Create a mini-world session for this player
          MiniWorldSession session = new MiniWorldSession(
              playerId, 
              username, 
              0.0, 64.0, 0.0
          );
          miniWorldSessions.put(playerId, session);
          
          logger.debug("[VERIFICATION] Created verification session for player {}", username);
        } else {
          logger.error("[VERIFICATION] Failed to enter player {} into virtual verification world", username);
          // Fall back to bypass verification
          verifiedPlayers.add(playerId);
          logger.warn("[VERIFICATION] Player {} verification bypassed due to virtual world error", username);
        }
      }
    } else {
      if (isVerified) {
        logger.debug("[VERIFICATION] Player {} already verified, skipping verification", username);
      } else if (isExempt) {
        logger.debug("[VERIFICATION] Player {} from exempt IP {}, skipping verification", username, address.getHostAddress());
      } else {
        logger.debug("[VERIFICATION] Mini-world verification disabled, marking {} as verified", username);
      }
      
      // Mark as verified immediately if we're not doing the check
      if (!verifiedPlayers.contains(playerId)) {
        verifiedPlayers.add(playerId);
        logger.debug("[VERIFICATION] Marked player {} as verified", username);
      }
    }
  }
  
  /**
   * Handle player disconnection event.
   *
   * @param event the disconnect event
   */
  @Subscribe
  public void onPlayerDisconnect(DisconnectEvent event) {
    if (!enabled) {
      return;
    }
    
    Player player = event.getPlayer();
    UUID playerId = player.getUniqueId();
    String username = player.getUsername();
    InetSocketAddress socketAddress = player.getRemoteAddress();
    InetAddress address = socketAddress.getAddress();
    String hostAddress = address.getHostAddress();
    
    // Check if this player was in verification
    MiniWorldSession session = miniWorldSessions.get(playerId);
    boolean wasInVerification = session != null;
    boolean wasVerified = verifiedPlayers.contains(playerId);
    boolean wasSuspicious = suspiciousPlayers.contains(playerId);
    
    logger.debug("[DISCONNECT] Player {} ({}) disconnecting from {}", username, playerId, hostAddress);
    
    // Check if player was in virtual verification world
    boolean wasInVirtualWorld = virtualWorld.isPlayerInVerificationWorld(playerId);
    if (wasInVirtualWorld) {
      logger.info("[DISCONNECT] Player {} disconnected from virtual verification world", username);
      virtualWorld.exitVerificationWorld((ConnectedPlayer) player);
    }
    
    if (wasInVerification) {
      long sessionDuration = System.currentTimeMillis() - session.startTime;
      boolean sessionCompleted = session.isCompleted();
      
      logger.info("[DISCONNECT] Player {} disconnected during verification", username);
      logger.debug("[DISCONNECT] Verification session details:");
      logger.debug("[DISCONNECT]   Duration: {} ms", sessionDuration);
      logger.debug("[DISCONNECT]   Completed: {}", sessionCompleted);
      logger.debug("[DISCONNECT]   Movement count: {}", session.movementCount);
      logger.debug("[DISCONNECT]   Interaction count: {}", session.interactionCount);
      logger.debug("[DISCONNECT]   Distance moved: {:.2f}", session.getDistanceMoved());
      
      if (!sessionCompleted) {
        logger.warn("[DISCONNECT] Player {} left verification early (potential bot behavior)", username);
      }
    } else if (wasVerified) {
      logger.debug("[DISCONNECT] Verified player {} disconnected", username);
    } else if (wasSuspicious) {
      logger.info("[DISCONNECT] Suspicious player {} disconnected", username);
    }
    
    // Decrement connection count
    AtomicInteger connections = connectionsByIp.get(address);
    if (connections != null) {
      int newCount = connections.decrementAndGet();
      logger.debug("[DISCONNECT] IP {} now has {} active connections", hostAddress, newCount);
      if (newCount <= 0) {
        connectionsByIp.remove(address);
        logger.debug("[DISCONNECT] Removed IP {} from connection tracking", hostAddress);
      }
    }
    
    // Clean up player state
    playerStates.remove(playerId);
    verifiedPlayers.remove(playerId);
    suspiciousPlayers.remove(playerId);
    failedChecks.remove(playerId);
    originalDestinations.remove(playerId);
    pendingTransfers.remove(playerId);
    
    // Clean up mini-world session
    miniWorldSessions.remove(playerId);
    
    logger.debug("[DISCONNECT] Cleaned up all tracking data for player {}", username);
  }
  
  /**
   * Process player movement for bot detection.
   * Note: PlayerMoveEvent doesn't exist in Velocity API.
   * We will rely on packet processing instead.
   */
  private void processPlayerMovement(Player player, double x, double y, double z, float yaw, float pitch) {
    if (!enabled) {
      return;
    }
    
    UUID playerId = player.getUniqueId();
    
    // Skip verified players
    if (verifiedPlayers.contains(playerId)) {
      return;
    }
    
    PlayerState state = playerStates.get(playerId);
    if (state == null) {
      state = new PlayerState(playerId, player.getRemoteAddress().getAddress());
      playerStates.put(playerId, state);
    }
    
    // Update position and rotation history using our custom tracking
    state.updatePositionAndRotation(x, y, z, yaw, pitch);
    
    // Perform checks if we have enough movement data
    if (state.hasEnoughData()) {
      if (config.isGravityCheckEnabled()) {
        performGravityCheck(player, state);
      }
      
      if (config.isYawCheckEnabled()) {
        performYawCheck(player, state);
      }
    }
  }
  
  /**
   * Process plugin messages for client brand detection.
   *
   * @param event the plugin message event
   */
  @Subscribe
  public void onPluginMessage(PluginMessageEvent event) {
    if (!enabled || !config.isClientBrandCheckEnabled()) {
      return;
    }
    
    // We only care about client brand messages from players
    if (!event.getIdentifier().equals("minecraft:brand") || !(event.getSource() instanceof Player)) {
      return;
    }
    
    Player player = (Player) event.getSource();
    UUID playerId = player.getUniqueId();
    
    // Skip if player is already verified
    if (verifiedPlayers.contains(playerId)) {
      return;
    }
    
    String brand = new String(event.getData());
    if (brand.length() > 0) {
      brand = brand.substring(1); // Skip the first byte (length)
    }
    
    // Check client brand against allowed brands
    if (config.getAllowedBrands().isEmpty() || config.getAllowedBrands().contains(brand)) {
      // Brand is allowed, mark player as verified
      verifiedPlayers.add(playerId);
      logger.debug("Player {} verified with brand: {}", playerId, brand);
    } else {
      // Brand is not allowed, mark as suspicious
      suspiciousPlayers.add(playerId);
      incrementFailedChecks(player);
      logger.debug("Player {} has suspicious brand: {}", playerId, brand);
    }
  }
  
  /**
   * Process server connection event for hitbox checks and handle verification world.
   *
   * @param event the server connected event
   */
  @Subscribe
  public void onServerConnected(ServerConnectedEvent event) {
    if (!enabled) {
      return;
    }
    
    Player player = event.getPlayer();
    UUID playerId = player.getUniqueId();
    RegisteredServer connectedServer = event.getServer();
    
    // Check if the player is in the virtual verification world
    if (virtualWorld.isPlayerInVerificationWorld(playerId)) {
      handleVirtualWorldConnection(player, connectedServer);
      return;
    }
    
    // For non-verification world connections
    
    // If this is a pending transfer after verification, complete the process
    if (pendingTransfers.remove(playerId)) {
      logger.info("Player {} successfully transferred to {} after verification", 
          player.getUsername(), connectedServer.getServerInfo().getName());
      return;
    }
    
    // Skip verified players for hitbox checks
    if (verifiedPlayers.contains(playerId) || !config.isHitboxCheckEnabled()) {
      return;
    }
    
    // Schedule hitbox check after player is fully connected
    PluginContainer plugin = server.getPluginManager().getPlugin("sentinalsproxy")
        .orElse(server.getPluginManager().getPlugin("velocity")
        .orElseThrow(() -> new IllegalStateException("Neither sentinalsproxy nor velocity plugin registered")));
    
    server.getScheduler().buildTask(plugin, () -> {
      if (player.isActive()) {
        performHitboxCheck(player);
      }
    }).delay(5, TimeUnit.SECONDS).schedule();
  }
  
  /**
   * Handle a player in the virtual verification world.
   * Enhanced with comprehensive debug logging inspired by Sonar anti-bot.
   * 
   * @param player the player
   * @param connectedServer the server they're trying to connect to
   */
  private void handleVirtualWorldConnection(Player player, RegisteredServer connectedServer) {
    UUID playerId = player.getUniqueId();
    InetSocketAddress remoteAddress = player.getRemoteAddress();
    InetAddress inetAddress = remoteAddress.getAddress();
    String hostAddress = inetAddress.getHostAddress();
    
    // Debug: Log connection details for virtual world
    logger.debug("[VIRTUAL-WORLD] Player {} ({}) in virtual verification world, attempting to connect to {}", 
        player.getUsername(), playerId, connectedServer.getServerInfo().getName());
    
    // Check if the player is still in verification
    MiniWorldSession session = miniWorldSessions.get(playerId);
    if (session == null) {
      logger.warn("[VIRTUAL-WORLD] Player {} has no verification session, bypassing verification", 
          player.getUsername());
      verifiedPlayers.add(playerId);
      virtualWorld.exitVerificationWorld((ConnectedPlayer) player);
      return;
    }
    
    // Check if verification is complete
    if (session.isCompleted() && session.isCheckPassed()) {
      logger.info("[VIRTUAL-WORLD] Player {} verification complete, transferring to target server", 
          player.getUsername());
      completeVerification(player, connectedServer);
    } else if (session.isCompleted() && !session.isCheckPassed()) {
      logger.warn("[VIRTUAL-WORLD] Player {} failed verification, denying connection", 
          player.getUsername());
      // Handle failed verification
      handleFailedVerification(player);
    } else {
      // Verification still in progress, keep player in virtual world
      logger.debug("[VIRTUAL-WORLD] Player {} verification still in progress", player.getUsername());
      
      // Set up timeout for verification if it doesn't complete normally
      PluginContainer plugin = server.getPluginManager().getPlugin("sentinalsproxy")
          .orElse(server.getPluginManager().getPlugin("velocity")
          .orElseThrow(() -> new IllegalStateException("Neither sentinalsproxy nor velocity plugin registered")));
      
      logger.debug("[VIRTUAL-WORLD] Setting up verification timeout of {} seconds for player {}",
          config.getMiniWorldDuration(), player.getUsername());
      
      // Schedule the verification timeout
      server.getScheduler().buildTask(plugin, () -> {
        logger.debug("[VIRTUAL-WORLD] Verification timeout triggered for player {}", player.getUsername());
        
        // Only proceed if the session is still active and not completed
        if (player.isActive() && miniWorldSessions.containsKey(playerId) && 
            !miniWorldSessions.get(playerId).isCompleted()) {
            
          logger.debug("[VIRTUAL-WORLD] Processing verification results for player {}", player.getUsername());
          
          // Check if the player has passed verification
          MiniWorldSession currentSession = miniWorldSessions.get(playerId);
          boolean passed = currentSession.isCheckPassed();
          
          // Log detailed verification analysis
          logger.debug("[VIRTUAL-WORLD] Player {} verification analysis:", player.getUsername());
          logger.debug("[VIRTUAL-WORLD]   Movement count: {}", currentSession.movementCount);
          logger.debug("[VIRTUAL-WORLD]   Interaction count: {}", currentSession.interactionCount);
          logger.debug("[VIRTUAL-WORLD]   Distance moved: {:.2f}", currentSession.getDistanceMoved());
          logger.debug("[VIRTUAL-WORLD]   Total path distance: {:.2f}", currentSession.getTotalPathDistance());
          logger.debug("[VIRTUAL-WORLD]   Movement complexity: {:.2f}", currentSession.getMovementComplexity());
          logger.debug("[VIRTUAL-WORLD]   Has jumped: {}", currentSession.hasJumped);
          logger.debug("[VIRTUAL-WORLD]   Has crouched: {}", currentSession.hasCrouched);
          logger.debug("[VIRTUAL-WORLD]   Has interacted: {}", currentSession.hasInteracted);
          logger.debug("[VIRTUAL-WORLD]   Natural timing: {}", currentSession.hasNaturalTiming());
          logger.debug("[VIRTUAL-WORLD]   Session duration: {} ms", 
              System.currentTimeMillis() - currentSession.startTime);
          logger.debug("[VIRTUAL-WORLD]   RESULT: {}", passed ? "PASSED" : "FAILED");
          
          // Mark session as complete
          currentSession.complete(passed);
          
          if (passed) {
            logger.info("[VIRTUAL-WORLD] Player {} PASSED verification check", player.getUsername());
            verifiedPlayers.add(playerId);
            transferToTargetServer(player);
          } else {
            logger.info("[VIRTUAL-WORLD] Player {} FAILED verification check", player.getUsername());
            if (config.isKickEnabled()) {
              logger.debug("[VIRTUAL-WORLD] Kicking player {} due to failed verification", player.getUsername());
              player.disconnect(Component.text(config.getKickMessage()));
            } else {
              // Still transfer, but mark as suspicious
              logger.debug("[VIRTUAL-WORLD] Marking player {} as suspicious and transferring", player.getUsername());
              suspiciousPlayers.add(playerId);
              transferToTargetServer(player);
            }
          }
        } else {
          logger.debug("[VIRTUAL-WORLD] Player {} no longer active or session already completed", 
              player.getUsername());
        }
      }).delay(config.getMiniWorldDuration(), TimeUnit.SECONDS).schedule();
    }
  }
  
  /**
   * Process player chat for additional bot detection.
   *
   * @param event the player chat event
   */
  @Subscribe
  public void onPlayerChat(PlayerChatEvent event) {
    if (!enabled) {
      return;
    }
    
    // Most bots don't chat, so this is a strong signal of a real player
    Player player = event.getPlayer();
    UUID playerId = player.getUniqueId();
    
    // Mark as verified if not suspicious
    if (!suspiciousPlayers.contains(playerId)) {
      verifiedPlayers.add(playerId);
      failedChecks.remove(playerId);
    }
  }
  
  /**
   * Perform gravity physics check on player movement.
   *
   * @param player the player to check
   * @param state the player state
   */
  private void performGravityCheck(Player player, PlayerState state) {
    // Skip if player is in creative or spectator mode (different physics)
    // Note: We don't have access to game mode directly in Velocity, this would need server implementation
    
    if (state.isFirstMove() || state.isOnGround()) {
      return; // Skip first moves or when player is on ground
    }
    
    // Simple gravity check - Y position should decrease when player is in air
    double lastY = state.getLastPosition().getY();
    double currentY = state.getCurrentPosition().getY();
    
    // If player is ascending, they might have jumped or used an item
    if (lastY < currentY && state.getSecondsSincePositiveYVelocity() > 1.5) {
      // Player has been ascending for too long - suspicious
      logger.debug("Player {} failed gravity check: ascending for too long", player.getUniqueId());
      incrementFailedChecks(player);
    }
    
    // Reset gravity timer if player is on ground now
    if (state.isOnGround()) {
      state.resetGravityViolation();
    }
  }
  
  /**
   * Perform yaw/rotation check for suspicious movements.
   *
   * @param player the player to check
   * @param state the player state
   */
  private void performYawCheck(Player player, PlayerState state) {
    // Skip checks for first few moves
    if (state.getMoveCount() < 5) {
      return;
    }
    
    // Check for impossibly quick rotations
    float lastYaw = state.getLastYaw();
    float currentYaw = state.getCurrentYaw();
    
    float yawDiff = Math.abs(lastYaw - currentYaw);
    if (yawDiff > 180) {
      yawDiff = 360 - yawDiff;
    }
    
    // Detect suspiciously precise or rapid rotations
    if (yawDiff > 160) {
      // Very fast 180 turn - suspicious
      state.incrementYawViolations();
      if (state.getYawViolations() >= 3) {
        logger.debug("Player {} failed yaw check: too many rapid rotations", player.getUniqueId());
        incrementFailedChecks(player);
        state.resetYawViolations();
      }
    }
    
    // Check for pattern-based movements (bots often use identical patterns)
    if (state.hasRepeatedRotationPattern()) {
      logger.debug("Player {} failed yaw check: repeated rotation pattern", player.getUniqueId());
      incrementFailedChecks(player);
    }
  }
  
  /**
   * Perform hitbox interaction check.
   *
   * @param player the player to check
   */
  private void performHitboxCheck(Player player) {
    // This would require more server-side integration to implement fully
    // Basic implementation: track suspicious behavior like no interactions
    UUID playerId = player.getUniqueId();
    PlayerState state = playerStates.get(playerId);
    
    if (state == null) {
      return;
    }
    
    // If player has been connected for > 1 minute with no interactions, that's suspicious
    if (state.getTimeSinceConnection() > 60 && state.getInteractionCount() == 0) {
      logger.debug("Player {} failed hitbox check: no interactions after 60 seconds", playerId);
      incrementFailedChecks(player);
    }
  }
  
  /**
   * Increment failed checks counter and take action if threshold is reached.
   *
   * @param player the player to check
   */
  private void incrementFailedChecks(Player player) {
    UUID playerId = player.getUniqueId();
    int fails = failedChecks.getOrDefault(playerId, 0) + 1;
    failedChecks.put(playerId, fails);
    
    logger.debug("Player {} has failed {} checks", playerId, fails);
    
    // Take action if threshold is reached
    if (fails >= kickThreshold) {
      if (config.isKickEnabled()) {
        player.disconnect(net.kyori.adventure.text.Component.text(config.getKickMessage()));
        logger.info("Kicked potential bot {} after failing {} checks", 
            player.getUsername(), fails);
      } else {
        suspiciousPlayers.add(playerId);
        logger.info("Player {} marked as potential bot after failing {} checks",
            player.getUsername(), fails);
      }
    }
  }
  
  /**
   * Clean up expired player states and perform maintenance.
   * This is called periodically to prevent memory leaks.
   */
  public void cleanup() {
    cleanupPlayerStates();
    cleanupMiniWorldSessions();
    cleanupConnectionData();
    cleanupVirtualWorld();
  }
  
  /**
   * Clean up expired player states.
   */
  private void cleanupPlayerStates() {
    long now = System.currentTimeMillis();
    playerStates.entrySet().removeIf(entry -> {
      // Remove player states older than 30 minutes (player likely disconnected)
      return entry.getValue().getLastUpdateTime() + TimeUnit.MINUTES.toMillis(30) < now;
    });
    
    logger.debug("Cleaned up player states, {} players being tracked", playerStates.size());
  }
  
  /**
   * Clean up connection rate tracking and throttling data.
   */
  private void cleanupConnectionData() {
    long now = System.currentTimeMillis();
    
    // Clean up old connection timestamps
    connectionTimestampsByIp.entrySet().removeIf(entry -> {
      List<Long> times = entry.getValue();
      times.removeIf(timestamp -> now - timestamp > TimeUnit.MINUTES.toMillis(10));
      return times.isEmpty();
    });
    
    // Reset throttled IPs after the configured throttle duration
    if (config.getThrottleDurationMs() > 0) {
      throttledIps.removeIf(ip -> 
          !connectionTimestampsByIp.containsKey(ip) || 
          connectionTimestampsByIp.get(ip).isEmpty() || 
          now - connectionTimestampsByIp.get(ip).get(connectionTimestampsByIp.get(ip).size() - 1) > config.getThrottleDurationMs());
    }
    
    // Clean up old latency data
    latencyByIp.entrySet().removeIf(entry -> 
        !connectionsByIp.containsKey(entry.getKey()) || 
        connectionsByIp.get(entry.getKey()).get() <= 0);
    
    // Clean up old DNS cache entries
    dnsResolveCache.entrySet().removeIf(entry -> 
        !connectionsByIp.containsKey(entry.getKey()) || 
        connectionsByIp.get(entry.getKey()).get() <= 0);
    
    // Periodically reset username pattern counts to prevent memory growth
    if (now % TimeUnit.HOURS.toMillis(1) < 60000) { // Reset approximately once per hour
      usernamePatternCounts.clear();
      logger.debug("Reset username pattern counts");
    }
    
    logger.debug("Cleaned up connection data - Tracking {} IPs, {} throttled", 
        connectionTimestampsByIp.size(), throttledIps.size());
  }
  
  /**
   * Clean up expired mini-world sessions.
   */
  private void cleanupMiniWorldSessions() {
    long now = System.currentTimeMillis();
    miniWorldSessions.entrySet().removeIf(entry -> {
      MiniWorldSession session = entry.getValue();
      
      // Remove completed sessions after 1 minute
      if (session.isCompleted()) {
        return now - session.startTime > TimeUnit.MINUTES.toMillis(1);
      }
      
      // Remove timed out sessions
      if (session.isTimedOut()) {
        logger.info("Mini-world session for player {} timed out and removed", session.playerName);
        return true;
      }
      
      return false;
    });
    
    logger.debug("Cleaned up mini-world sessions, {} sessions active", miniWorldSessions.size());
  }
  
  /**
   * Clean up expired virtual world players.
   */
  private void cleanupVirtualWorld() {
    virtualWorld.cleanup();
    logger.debug("Cleaned up virtual verification world");
  }
  
  /**
   * Process a packet for bot detection.
   *
   * @param ctx the channel handler context
   * @param packet the packet to check
   * @param player the connected player
   * @return true if packet should be blocked, false otherwise
   */
  public boolean handlePacket(ChannelHandlerContext ctx, Object packet, ConnectedPlayer player) {
    if (!enabled || player == null) {
      return false;
    }
    
    UUID playerId = player.getUniqueId();
    
    // Skip verified players
    if (verifiedPlayers.contains(playerId)) {
      return false;
    }
    
    // Get or create player state
    PlayerState state = playerStates.computeIfAbsent(
        playerId, 
        id -> new PlayerState(id, player.getRemoteAddress().getAddress())
    );
    
    // Process different packet types
    String packetName = packet.getClass().getSimpleName();
    
    // Check if player is in mini-world and process relevant packets
    MiniWorldSession miniWorldSession = miniWorldSessions.get(playerId);
    if (miniWorldSession != null && !miniWorldSession.isCompleted()) {
      // Player is in mini-world check, analyze packets for mini-world activity
      
      if (packetName.contains("Position") && !packetName.contains("Rotation")) {
        // Position packet - extract position and update mini-world
        // In a real implementation, we'd extract x, y, z from the packet
        // For demo purposes, we'll use some dummy values to simulate movement
        double x = Math.random() * 5.0;  // Simulate some random movement
        double y = 64.0 + Math.random(); // Simulate some vertical movement
        double z = Math.random() * 5.0;  // Simulate some random movement
        processMiniWorldMovement(player, x, y, z);
      } else if (packetName.contains("Rotation") && !packetName.contains("Position")) {
        // Just rotation, count as interaction
        state.incrementInteractionCount();
      } else if (packetName.contains("Position") && packetName.contains("Rotation")) {
        // Combined position and rotation
        double x = Math.random() * 5.0;
        double y = 64.0 + Math.random();
        double z = Math.random() * 5.0;
        processMiniWorldMovement(player, x, y, z);
      } else if (packetName.contains("Action") || packetName.contains("BlockPlace") || 
                packetName.contains("UseItem") || packetName.contains("Animation")) {
        // Player performed an interaction in the mini-world
        processMiniWorldInteraction(player);
      }
    }
    
    // Continue with normal packet processing
    if (packetName.contains("Position") && !packetName.contains("Rotation")) {
      // Position-only packet
      state.incrementInteractionCount();
    } else if (packetName.contains("Rotation") && !packetName.contains("Position")) {
      // Rotation-only packet
      state.incrementInteractionCount();
    } else if (packetName.contains("Position") && packetName.contains("Rotation")) {
      // Combined position and rotation packet
      state.incrementInteractionCount();
    } else if (packet instanceof PluginMessagePacket) {
      PluginMessagePacket msgPacket = (PluginMessagePacket) packet;
      state.incrementInteractionCount();
      
      // Check for client brand message
      if (config.isClientBrandCheckEnabled() && "minecraft:brand".equals(msgPacket.getChannel())) {
        ByteBuf data = msgPacket.content();
        byte[] bytes = new byte[data.readableBytes()];
        data.getBytes(data.readerIndex(), bytes);
        String brand = new String(bytes);
        if (brand.length() > 0) {
          brand = brand.substring(1); // Skip the first byte (length)
        }
        
        if (config.getAllowedBrands().isEmpty() || config.getAllowedBrands().contains(brand)) {
          verifiedPlayers.add(playerId);
        } else {
          suspiciousPlayers.add(playerId);
          incrementFailedChecks(player);
        }
      }
    }
    
    // Run checks if we have enough data
    if (state.hasEnoughData()) {
      if (config.isGravityCheckEnabled()) {
        performGravityCheck(player, state);
      }
      
      if (config.isYawCheckEnabled()) {
        performYawCheck(player, state);
      }
    }
    
    // Check if this player has failed too many checks
    return failedChecks.getOrDefault(playerId, 0) >= kickThreshold && config.isKickEnabled();
  }
  
  /**
   * Configure the AntiBot with new settings.
   *
   * @param config the new configuration
   */
  public void configure(AntiBotConfig config) {
    this.config = config;
    this.enabled = config.isEnabled();
    this.kickThreshold = config.getKickThreshold();
    
    logger.info("AntiBot reconfigured with {} checks enabled", 
        (config.isGravityCheckEnabled() ? 1 : 0) + 
        (config.isHitboxCheckEnabled() ? 1 : 0) + 
        (config.isYawCheckEnabled() ? 1 : 0) + 
        (config.isClientBrandCheckEnabled() ? 1 : 0));
  }
  
  /**
   * Reports the current status of this module.
   */
  public void reportStatus() {
    logger.info("[AntiBot] Status Report:");
    logger.info("[AntiBot] - Active: {}", enabled);
    logger.info("[AntiBot] - Players being tracked: {}", playerStates.size());
    logger.info("[AntiBot] - Verified players: {}", verifiedPlayers.size());
    logger.info("[AntiBot] - Suspicious players: {}", suspiciousPlayers.size());
    logger.info("[AntiBot] - Active mini-world sessions: {}", miniWorldSessions.size());
    logger.info("[AntiBot] - Connections by IP count: {}", connectionsByIp.size());
    
    // Report configuration
    if (enabled) {
      logger.info("[AntiBot] - Configuration:");
      logger.info("[AntiBot]   - Gravity checks: {}", config.isGravityCheckEnabled());
      logger.info("[AntiBot]   - Hitbox checks: {}", config.isHitboxCheckEnabled());
      logger.info("[AntiBot]   - Rotation checks: {}", config.isYawCheckEnabled());
      logger.info("[AntiBot]   - Client brand checks: {}", config.isClientBrandCheckEnabled());
      logger.info("[AntiBot]   - Mini-world checks: {}", config.isMiniWorldCheckEnabled());
      logger.info("[AntiBot]   - Check only first join: {}", config.isCheckOnlyFirstJoin());
    }
    
    // Report any active mini-world sessions
    if (!miniWorldSessions.isEmpty()) {
      logger.info("[AntiBot] - Active mini-world sessions:");
      miniWorldSessions.forEach((id, session) -> {
        logger.info("[AntiBot]   - Player: {}, Time: {}/{} sec, Movements: {}, Completed: {}, Passed: {}", 
            session.playerName, session.getElapsedSeconds(), config.getMiniWorldDuration(),
            session.movementCount, session.isCompleted(), session.isPassed());
      });
    }
  }
  
  /**
   * Gets whether the AntiBot system is enabled.
   *
   * @return whether the system is enabled
   */
  public boolean isEnabled() {
    return enabled;
  }
  
  /**
   * Sets whether the AntiBot system is enabled.
   *
   * @param enabled whether the system should be enabled
   */
  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
    logger.info("AntiBot protection is now {}", enabled ? "enabled" : "disabled");
  }
  
  /**
   * Gets the current configuration.
   *
   * @return the AntiBot configuration
   */
  public AntiBotConfig getConfig() {
    return config;
  }
  
  /**
   * Mark a player as verified from the virtual world.
   * This method is called by VirtualVerificationWorld when verification is complete.
   * 
   * @param playerId the player to mark as verified
   */
  public void markPlayerAsVerified(UUID playerId) {
    verifiedPlayers.add(playerId);
    
    // Get the mini-world session to complete verification
    MiniWorldSession session = miniWorldSessions.get(playerId);
    if (session != null) {
      session.setCompleted(true);
      session.setCheckPassed(true);
      
      logger.info("[VERIFICATION] Player {} marked as verified by virtual world", session.username);
    }
  }
  
  /**
   * Complete verification process and transfer player to target server.
   *
   * @param player the player to verify
   * @param targetServer the target server to connect to
   */
  private void completeVerification(Player player, RegisteredServer targetServer) {
    UUID playerId = player.getUniqueId();
    
    // Mark as verified
    verifiedPlayers.add(playerId);
    failedChecks.remove(playerId);
    
    // Add to pending transfers to track successful connection
    pendingTransfers.add(playerId);
    
    // Clean up session
    miniWorldSessions.remove(playerId);
    
    // Transfer player to target server
    transferToTargetServer(player, targetServer);
  }
  
  /**
   * Transfer player to target server.
   *
   * @param player the player to transfer
   */
  private void transferToTargetServer(Player player) {
    UUID playerId = player.getUniqueId();
    RegisteredServer targetServer = originalDestinations.get(playerId);
    
    if (targetServer == null) {
      // Try to find a fallback server
      Optional<RegisteredServer> fallback = server.getServer("lobby")
          .or(() -> server.getAllServers().stream().findFirst());
      
      if (fallback.isPresent()) {
        targetServer = fallback.get();
      } else {
        logger.error("[TRANSFER] No target server found for player {}", player.getUsername());
        player.disconnect(Component.text("No target server available. Please try again later."));
        return;
      }
    }
    
    transferToTargetServer(player, targetServer);
  }
  
  /**
   * Transfer player to a specific target server.
   *
   * @param player the player to transfer
   * @param targetServer the target server to connect to
   */
  private void transferToTargetServer(Player player, RegisteredServer targetServer) {
    UUID playerId = player.getUniqueId();
    
    logger.info("[TRANSFER] Transferring player {} to server {}", 
        player.getUsername(), targetServer.getServerInfo().getName());
    
    // Remove from verification world
    virtualWorld.exitVerificationWorld((ConnectedPlayer) player);
    
    // Add to pending transfers to track successful connection
    pendingTransfers.add(playerId);
    
    // Connect player to target server
    player.createConnectionRequest(targetServer).fireAndForget();
  }
  
  /**
   * Handle failed verification by either kicking the player or marking as suspicious.
   *
   * @param player the player who failed verification
   */
  private void handleFailedVerification(Player player) {
    UUID playerId = player.getUniqueId();
    
    // Clean up session
    miniWorldSessions.remove(playerId);
    originalDestinations.remove(playerId);
    
    // Remove from verification world
    virtualWorld.exitVerificationWorld((ConnectedPlayer) player);
    
    // Mark as suspicious
    suspiciousPlayers.add(playerId);
    
    if (config.isKickEnabled()) {
      logger.info("[VERIFICATION] Player {} failed verification and will be kicked", player.getUsername());
      player.disconnect(Component.text(config.getKickMessage()));
    } else {
      logger.info("[VERIFICATION] Player {} failed verification but will be allowed to connect as suspicious", 
          player.getUsername());
      transferToTargetServer(player);
    }
  }
  
  /**
   * Process player movement in the virtual verification world.
   * 
   * @param player the player who moved
   * @param x new X coordinate
   * @param y new Y coordinate
   * @param z new Z coordinate
   */
  private void processMiniWorldMovement(Player player, double x, double y, double z) {
    UUID playerId = player.getUniqueId();
    String username = player.getUsername();
    
    // Check if player is in virtual world
    if (!virtualWorld.isPlayerInVerificationWorld(playerId)) {
      return;
    }
    
    // Update virtual world position and check for verification completion
    Vector3d newPosition = new Vector3d(x, y, z);
    boolean verificationComplete = virtualWorld.handlePlayerMovement((ConnectedPlayer) player, newPosition);
    
    // Update mini-world session
    MiniWorldSession session = miniWorldSessions.get(playerId);
    if (session != null) {
      session.updatePosition(x, y, z);
      session.incrementMovement();
      
      if (config.isDebugMode()) {
        logger.debug("[VIRTUAL-MOVEMENT] Player {} moved to [{}, {}, {}], movements: {}", 
            username, x, y, z, session.movementCount);
      }
      
      if (verificationComplete) {
        session.setCompleted(true);
        session.setCheckPassed(true);
        
        logger.info("[VIRTUAL-MOVEMENT] Player {} completed verification through virtual world", username);
        
        // Find target server and complete verification
        RegisteredServer originalDestination = originalDestinations.get(playerId);
        if (originalDestination != null) {
          completeVerification(player, originalDestination);
        } else {
          // Try to find a fallback server
          Optional<RegisteredServer> fallback = server.getServer("lobby")
              .or(() -> server.getAllServers().stream().findFirst());
          
          if (fallback.isPresent()) {
            completeVerification(player, fallback.get());
          } else {
            logger.error("[VIRTUAL-MOVEMENT] No target server found for verified player {}", username);
            handleFailedVerification(player);
          }
        }
      }
    }
  }
  
  private void processMiniWorldInteraction(Player player) {
    UUID playerId = player.getUniqueId();
    
    // Check if player is in mini-world check
    MiniWorldSession session = miniWorldSessions.get(playerId);
    if (session != null && !session.isCompleted()) {
      session.incrementInteraction();
      session.hasInteracted = true;
      
      if (config.isDebugMode()) {
        logger.debug("[VIRTUAL-INTERACTION] Player {} performed an interaction in virtual world", 
            player.getUsername());
      }
    }
  }
  
  /**
   * Inner class to represent a mini-world verification session.
   * Tracks player movement and interaction during verification.
   */
  class MiniWorldSession {
    final UUID playerId;
    final String playerName;
    final String username;
    final long startTime;
    
    private Vector3d initialPosition;
    private Vector3d currentPosition;
    private Vector3d lastPosition;
    private double maxDistanceFromStart;
    private double totalDistance;
    
    int movementCount;
    int interactionCount;
    boolean hasJumped;
    boolean hasCrouched;
    boolean hasInteracted;
    boolean checkPassed;
    boolean completed;
    private final Queue<Long> moveTimestamps = new LinkedList<>();
    
    /**
     * Creates a new mini-world session.
     *
     * @param playerId the UUID of the player
     * @param playerName the name of the player
     * @param x the initial x coordinate
     * @param y the initial y coordinate
     * @param z the initial z coordinate
     */
    public MiniWorldSession(UUID playerId, String playerName, double x, double y, double z) {
      this.playerId = playerId;
      this.playerName = playerName;
      this.username = playerName;
      this.startTime = System.currentTimeMillis();
      this.initialPosition = new Vector3d(x, y, z);
      this.currentPosition = initialPosition;
      this.lastPosition = initialPosition;
      this.movementCount = 0;
      this.interactionCount = 0;
      this.maxDistanceFromStart = 0;
      this.totalDistance = 0;
      this.hasJumped = false;
      this.hasCrouched = false;
      this.hasInteracted = false;
      this.checkPassed = false;
      this.completed = false;
    }
    
    /**
     * Updates the position of the player.
     *
     * @param x the new x coordinate
     * @param y the new y coordinate
     * @param z the new z coordinate
     */
    public void updatePosition(double x, double y, double z) {
      lastPosition = currentPosition;
      currentPosition = new Vector3d(x, y, z);
      
      // Calculate distance moved
      double distanceFromStart = initialPosition.distance(currentPosition);
      double lastMoveDist = lastPosition.distance(currentPosition);
      
      // Update max distance
      maxDistanceFromStart = Math.max(maxDistanceFromStart, distanceFromStart);
      
      // Update total path distance
      totalDistance += lastMoveDist;
      
      // Check for jumping or crouching
      if (y > lastPosition.getY() + 0.4) {
        hasJumped = true;
      } else if (y < lastPosition.getY() - 0.3 && y < lastPosition.getY()) {
        hasCrouched = true;
      }
      
      // Record timestamp for this movement
      moveTimestamps.add(System.currentTimeMillis());
      if (moveTimestamps.size() > 20) { // Keep only last 20 timestamps
        moveTimestamps.poll();
      }
    }
    
    /**
     * Increments the movement count.
     */
    public void incrementMovement() {
      movementCount++;
    }
    
    /**
     * Increments the interaction count.
     */
    public void incrementInteraction() {
      interactionCount++;
    }
    
    /**
     * Gets the total distance moved.
     *
     * @return the total distance moved
     */
    public double getDistanceMoved() {
      return maxDistanceFromStart;
    }
    
    /**
     * Gets the total path distance.
     *
     * @return the total path distance
     */
    public double getTotalPathDistance() {
      return totalDistance;
    }
    
    /**
     * Gets the movement complexity (ratio of total path to direct distance).
     *
     * @return the movement complexity
     */
    public double getMovementComplexity() {
      if (maxDistanceFromStart < 0.1) {
        return 1.0;
      }
      return totalDistance / maxDistanceFromStart;
    }
    
    /**
     * Gets whether the player has natural timing between movements.
     * Bots often move at perfect intervals.
     *
     * @return whether the player has natural timing
     */
    public boolean hasNaturalTiming() {
      if (moveTimestamps.size() < 5) {
        return false;
      }
      
      // Convert queue to array for easier processing
      Long[] timestamps = moveTimestamps.toArray(new Long[0]);
      long[] diffs = new long[timestamps.length - 1];
      
      for (int i = 0; i < timestamps.length - 1; i++) {
        diffs[i] = timestamps[i + 1] - timestamps[i];
      }
      
      // Calculate variance in timing
      double mean = 0;
      for (long diff : diffs) {
        mean += diff;
      }
      mean /= diffs.length;
      
      double variance = 0;
      for (long diff : diffs) {
        variance += Math.pow(diff - mean, 2);
      }
      variance /= diffs.length;
      
      // Natural human movement has some variance in timing
      return variance > 1000; // At least 1000ms^2 variance
    }
    
    /**
     * Gets the elapsed time in seconds.
     *
     * @return the elapsed time in seconds
     */
    public int getElapsedSeconds() {
      return (int) ((System.currentTimeMillis() - startTime) / 1000);
    }
    
    /**
     * Checks if the verification is timed out.
     *
     * @return whether the verification is timed out
     */
    public boolean isTimedOut() {
      return getElapsedSeconds() > MINIWORLD_CHECK_DURATION_SECONDS * 2;
    }
    
    /**
     * Checks if the verification session is completed.
     *
     * @return whether the verification is completed
     */
    public boolean isCompleted() {
      return completed;
    }
    
    /**
     * Sets whether the verification session is completed.
     *
     * @param completed whether the verification is completed
     */
    public void setCompleted(boolean completed) {
      this.completed = completed;
    }
    
    /**
     * Completes the verification session with the specified result.
     *
     * @param passed whether the verification was passed
     */
    public void complete(boolean passed) {
      this.completed = true;
      this.checkPassed = passed;
    }
    
    /**
     * Checks if the verification is considered passed.
     * This evaluates movement, interactions, and other metrics.
     *
     * @return whether the verification is passed
     */
    public boolean isCheckPassed() {
      if (movementCount < MINIWORLD_MIN_MOVEMENTS) {
        return false;
      }
      
      if (getDistanceMoved() < MINIWORLD_MIN_DISTANCE) {
        return false;
      }
      
      // Check for some interaction, decent movement, or signs of human behavior
      return hasJumped || hasInteracted || interactionCount > 2 || hasNaturalTiming();
    }
    
    /**
     * Gets whether the verification has been passed.
     *
     * @return whether the verification has been passed
     */
    public boolean isPassed() {
      return checkPassed;
    }
    
    /**
     * Sets whether the verification check has passed.
     *
     * @param checkPassed whether the verification has passed
     */
    public void setCheckPassed(boolean checkPassed) {
      this.checkPassed = checkPassed;
    }
  }
  
  /**
   * Gets all active mini-world sessions.
   *
   * @return map of player UUIDs to mini-world sessions
   */
  public Map<UUID, MiniWorldSession> getMiniWorldSessions() {
    return miniWorldSessions;
  }
  
  /**
   * Gets a mini-world session for a specific player.
   *
   * @param playerId the player UUID
   * @return the mini-world session, or null if not found
   */
  public MiniWorldSession getMiniWorldSession(UUID playerId) {
    return miniWorldSessions.get(playerId);
  }
}
