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
  // NOTE: The verification world/server (antibot-verification) MUST be registered in your Velocity config:
  // Example:
  // [servers]
  //   antibot-verification = "localhost:25570"
  //
  // If this server is not present, verification will be bypassed and a warning will be logged.

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
   * Handle a player connecting to the verification world.
   * Enhanced with comprehensive debug logging inspired by Sonar anti-bot.
   * 
   * @param player the player
   * @param verificationServer the verification server
   */
  private void handleVerificationWorldConnection(Player player, RegisteredServer verificationServer) {
    UUID playerId = player.getUniqueId();
    InetSocketAddress remoteAddress = player.getRemoteAddress();
    InetAddress inetAddress = remoteAddress.getAddress();
    String hostAddress = inetAddress.getHostAddress();
    
    // Debug: Log initial connection details
    logger.debug("[LOBBY-JOIN] Player {} ({}) connecting to verification world from {}", 
        player.getUsername(), playerId, hostAddress);
    logger.debug("[LOBBY-JOIN] Remote address: {}, Server: {}", 
        remoteAddress, verificationServer.getServerInfo().getName());
    
    // Check if the player is in our tracking map
    MiniWorldSession session = miniWorldSessions.get(playerId);
    boolean isNewSession = session == null;
    
    if (isNewSession) {
      // Create a new session if one doesn't exist
      session = new MiniWorldSession(playerId, player.getUsername(), 0.0, 64.0, 0.0);
      miniWorldSessions.put(playerId, session);
      
      logger.info("[LOBBY-JOIN] Created new verification session for player {} ({})", 
          player.getUsername(), playerId);
      logger.debug("[LOBBY-JOIN] Session details - Start position: [{}, {}, {}], Start time: {}", 
          session.startX, session.startY, session.startZ, session.startTime);
    } else {
      logger.debug("[LOBBY-JOIN] Existing verification session found for player {} ({})", 
          player.getUsername(), playerId);
      logger.debug("[LOBBY-JOIN] Session state - Completed: {}, Passed: {}, Movement count: {}, Interaction count: {}", 
          session.isCompleted(), session.isCheckPassed(), session.movementCount, session.interactionCount);
    }
    
    // Log current connection statistics for this IP
    AtomicInteger ipConnections = connectionsByIp.get(inetAddress);
    int currentConnections = ipConnections != null ? ipConnections.get() : 0;
    logger.debug("[LOBBY-JOIN] IP {} currently has {} active connections", hostAddress, currentConnections);
    
    // Log player state
    boolean isVerified = verifiedPlayers.contains(playerId);
    boolean isSuspicious = suspiciousPlayers.contains(playerId);
    int failCount = failedChecks.getOrDefault(playerId, 0);
    
    logger.debug("[LOBBY-JOIN] Player state - Verified: {}, Suspicious: {}, Failed checks: {}", 
        isVerified, isSuspicious, failCount);
    
    // Check if this is a reconnection to verification world
    if (!isNewSession && session.isCompleted()) {
      logger.warn("[LOBBY-JOIN] Player {} attempting to rejoin verification world after completion", 
          player.getUsername());
    }
    
    logger.info("[LOBBY-JOIN] Player {} connected to verification world (session: {})", 
        player.getUsername(), isNewSession ? "NEW" : "EXISTING");
    
    // Send welcome message explaining the verification
    player.sendMessage(Component.text("------------------------------", NamedTextColor.GOLD));
    player.sendMessage(Component.text("Welcome to the verification area!", NamedTextColor.GREEN)
        .decoration(TextDecoration.BOLD, true));
    player.sendMessage(Component.text("Please move around and interact with the world.", NamedTextColor.WHITE));
    player.sendMessage(Component.text("You will be transferred to the main server shortly.", NamedTextColor.WHITE));
    player.sendMessage(Component.text("------------------------------", NamedTextColor.GOLD));
    logger.debug("[LOBBY-JOIN] Sent welcome message to player {}", player.getUsername());
    
    // Schedule a check task
    PluginContainer plugin = server.getPluginManager().getPlugin("sentinalsproxy")
        .orElse(server.getPluginManager().getPlugin("velocity").orElse(null));
    
    if (plugin != null) {
      logger.debug("[LOBBY-JOIN] Scheduling verification timeout task for player {} (duration: {} seconds)", 
          player.getUsername(), config.getMiniWorldDuration());
      
      // Schedule the verification timeout
      server.getScheduler().buildTask(plugin, () -> {
        logger.debug("[LOBBY-TIMEOUT] Verification timeout triggered for player {}", player.getUsername());
        
        // Only proceed if the session is still active and not completed
        if (player.isActive() && miniWorldSessions.containsKey(playerId) && 
            !miniWorldSessions.get(playerId).isCompleted()) {
            
          logger.debug("[LOBBY-TIMEOUT] Processing verification results for player {}", player.getUsername());
          
          // Check if the player has passed verification
          MiniWorldSession currentSession = miniWorldSessions.get(playerId);
          boolean passed = currentSession.isCheckPassed();
          
          // Log detailed verification analysis
          logger.debug("[LOBBY-ANALYSIS] Player {} verification analysis:", player.getUsername());
          logger.debug("[LOBBY-ANALYSIS]   Movement count: {}", currentSession.movementCount);
          logger.debug("[LOBBY-ANALYSIS]   Interaction count: {}", currentSession.interactionCount);
          logger.debug("[LOBBY-ANALYSIS]   Distance moved: {:.2f}", currentSession.getDistanceMoved());
          logger.debug("[LOBBY-ANALYSIS]   Total path distance: {:.2f}", currentSession.getTotalPathDistance());
          logger.debug("[LOBBY-ANALYSIS]   Movement complexity: {:.2f}", currentSession.getMovementComplexity());
          logger.debug("[LOBBY-ANALYSIS]   Has jumped: {}", currentSession.hasJumped);
          logger.debug("[LOBBY-ANALYSIS]   Has crouched: {}", currentSession.hasCrouched);
          logger.debug("[LOBBY-ANALYSIS]   Has interacted: {}", currentSession.hasInteracted);
          logger.debug("[LOBBY-ANALYSIS]   Natural timing: {}", currentSession.hasNaturalTiming());
          logger.debug("[LOBBY-ANALYSIS]   Session duration: {} ms", 
              System.currentTimeMillis() - currentSession.startTime);
          logger.debug("[LOBBY-ANALYSIS]   RESULT: {}", passed ? "PASSED" : "FAILED");
          
          // Mark session as complete
          currentSession.complete(passed);
          
          if (passed) {
            logger.info("[LOBBY-RESULT] Player {} PASSED verification check", player.getUsername());
            verifiedPlayers.add(playerId);
            transferToTargetServer(player);
          } else {
            logger.info("[LOBBY-RESULT] Player {} FAILED verification check", player.getUsername());
            if (config.isKickEnabled()) {
              logger.debug("[LOBBY-RESULT] Kicking player {} due to failed verification", player.getUsername());
              player.disconnect(Component.text(config.getKickMessage()));
            } else {
              // Still transfer, but mark as suspicious
              logger.debug("[LOBBY-RESULT] Marking player {} as suspicious and transferring", player.getUsername());
              suspiciousPlayers.add(playerId);
              transferToTargetServer(player);
            }
          }
        } else {
          logger.debug("[LOBBY-TIMEOUT] Player {} no longer active or session already completed", 
              player.getUsername());
        }
      }).delay(config.getMiniWorldDuration(), TimeUnit.SECONDS).schedule();
    } else {
      logger.error("[LOBBY-JOIN] No plugin found to schedule verification tasks for player {}", 
          player.getUsername());
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
   * Manually checks a player against all active checks.
   *
   * @param player the player to check
   * @return true if the player passes all checks, false otherwise
   */
  public boolean checkPlayer(Player player) {
    if (!enabled) {
      return true;
    }
    
    UUID playerId = player.getUniqueId();
    
    // If player is already verified, they pass
    if (verifiedPlayers.contains(playerId)) {
      return true;
    }
    
    // If player is currently in mini-world check, report status
    if (miniWorldSessions.containsKey(playerId)) {
      MiniWorldSession session = miniWorldSessions.get(playerId);
      
      // Report the current mini-world session state
      if (!session.isCompleted()) {
        logger.info("Player {} is currently in mini-world check ({}/{} sec, {} movements)", 
            player.getUsername(), session.getElapsedSeconds(), config.getMiniWorldDuration(),
            session.movementCount);
        return false; // Check is still in progress
      } else {
        // Session is complete, return the result
        return session.isPassed();
      }
    }
    
    // Make sure we have a player state
    PlayerState state = playerStates.get(playerId);
    if (state == null) {
      state = new PlayerState(playerId, 
          ((InetSocketAddress)player.getRemoteAddress()).getAddress());
      playerStates.put(playerId, state);
    }
    
    // Run all active checks   
    boolean passed = true;
    
    if (config.isGravityCheckEnabled()) {
      passed = passed && checkGravity(player, state);
    }
    
    if (config.isYawCheckEnabled()) {
      passed = passed && checkYaw(player, state);
    }
    
    if (config.isHitboxCheckEnabled()) {
      passed = passed && checkHitbox(player, state);
    }
    
    if (config.isClientBrandCheckEnabled()) {
      passed = passed && checkClientBrand(player, state);
    }
    
    // Start mini-world check if configured and not already verified
    if (config.isMiniWorldCheckEnabled() && passed) {
      logger.info("Starting mini-world check for player {} as part of manual verification", 
          player.getUsername());
      startMiniWorldCheck(player);
      
      // The check is now in progress
      return false;
    }
    
    if (!passed) {
      logger.info("Player {} failed anti-bot checks", player.getUsername());
      if (config.isKickOnFailure()) {
        player.disconnect(Component.text(config.getKickMessage()));
      }
    }
    
    return passed;
  }
  
  /**
   * Check player's gravity movement for potential violations.
   *
   * @param player the player to check
   * @param state the player's state
   * @return true if the check passes, false if it fails
   */
  private boolean checkGravity(Player player, PlayerState state) {
    if (state.isFirstMove() || state.isOnGround() || state.getMoveCount() < 5) {
      return true; // Not enough data to check
    }
    
    double lastY = state.getLastPosition().getY();
    double currentY = state.getCurrentPosition().getY();
    
    // If player is ascending for too long without being on ground
    if (lastY < currentY && state.getSecondsSincePositiveYVelocity() > 2.0) {
      logger.debug("Player {} failed gravity check: ascending for too long", player.getUsername());
      return false;
    }
    
    return true;
  }
  
  /**
   * Check player's yaw/rotation for suspicious patterns.
   *
   * @param player the player to check
   * @param state the player's state
   * @return true if the check passes, false if it fails
   */
  private boolean checkYaw(Player player, PlayerState state) {
    if (state.getMoveCount() < 10) {
      return true; // Not enough data
    }
    
    // Check for bot-like rotation patterns
    if (state.hasRepeatedRotationPattern()) {
      logger.debug("Player {} failed yaw check: suspicious rotation pattern", player.getUsername());
      return false;
    }
    
    // Check for impossibly fast rotations
    float yawDiff = Math.abs(state.getLastYaw() - state.getCurrentYaw());
    if (yawDiff > 170 && state.getYawViolations() >= 3) {
      logger.debug("Player {} failed yaw check: too many rapid rotations", player.getUsername());
      return false;
    }
    
    return true;
  }
  
  /**
   * Check player's hitbox interactions.
   *
   * @param player the player to check
   * @param state the player's state
   * @return true if the check passes, false if it fails
   */
  private boolean checkHitbox(Player player, PlayerState state) {
    // This would require more context about player interactions
    // Simplified implementation for now
    if (state.getInteractionCount() == 0 && state.getTimeSinceConnection() > 60) {
      logger.debug("Player {} failed hitbox check: no interactions after 60 seconds", player.getUsername());
      return false;
    }
    
    return true;
  }
  
  /**
   * Check player's client brand.
   *
   * @param player the player to check
   * @param state the player's state
   * @return true if the check passes, false if it fails
   */
  private boolean checkClientBrand(Player player, PlayerState state) {
    String brand = state.getClientBrand();
    
    // If we don't have the brand yet or no restrictions, pass
    if (brand == null || config.getAllowedBrands().isEmpty()) {
      return true;
    }
    
    // Check if this brand is allowed
    if (!config.getAllowedBrands().contains(brand.toLowerCase())) {
      logger.debug("Player {} failed client brand check: {} not in allowed list", 
          player.getUsername(), brand);
      return false;
    }
    
    return true;
  }
  
  /**
   * Start a mini-world environment check for a player.
   * 
   * @param player the player to check
   * @return true if the check was started, false if it couldn't be started
   */
  public boolean startMiniWorldCheck(Player player) {
    if (!enabled || !config.isMiniWorldCheckEnabled()) {
      return false;
    }
    
    UUID playerId = player.getUniqueId();
    
    // Skip if already in a mini-world session or already verified
    if (miniWorldSessions.containsKey(playerId) || verifiedPlayers.contains(playerId)) {
      return false;
    }
    
    // Get player position (would come from the connecting server in real implementation)
    // Here we use dummy coordinates since we don't have direct access
    double x = 0.0;
    double y = 64.0; // Default world height
    double z = 0.0;
    
    // Create new session
    MiniWorldSession session = new MiniWorldSession(playerId, player.getUsername(), x, y, z);
    miniWorldSessions.put(playerId, session);
    
    // Log the start of a mini-world check
    logger.info("Starting mini-world check for player {} ({})", player.getUsername(), playerId);
    
    // In a real implementation, here we would:
    // 1. Save the player's original position
    // 2. Teleport them to a special test environment
    // 3. Send them instructions
    
    // Log what would happen in a real implementation
    logger.debug("Would teleport {} to mini-world environment at [{}, {}, {}]", 
        player.getUsername(), x, y, z);
    
    // Schedule a task to clean up the session after the timeout period
    PluginContainer plugin = server.getPluginManager().getPlugin("sentinalsproxy")
        .orElse(server.getPluginManager().getPlugin("velocity").orElse(null));
    
    if (plugin != null) {
      server.getScheduler().buildTask(plugin, () -> {
        MiniWorldSession existingSession = miniWorldSessions.get(playerId);
        if (existingSession != null && !existingSession.isCompleted()) {
          // Session timed out - mark as failed
          existingSession.complete(false);
          handleMiniWorldResult(player, false);
        }
      }).delay(config.getMiniWorldDuration() + 2, TimeUnit.SECONDS).schedule();
    }
    
    return true;
  }
  
  /**
   * Transfer a player to their target server after verification.
   * 
   * @param player the player to transfer
   */
  private void transferToTargetServer(Player player) {
    UUID playerId = player.getUniqueId();
    String username = player.getUsername();
    
    logger.debug("[TRANSFER] Initiating transfer for player {}", username);
    
    // Get the original destination server
    RegisteredServer targetServer = originalDestinations.remove(playerId);
    
    if (targetServer != null) {
      logger.debug("[TRANSFER] Using stored original destination for {}: {}", 
          username, targetServer.getServerInfo().getName());
    }
    
    // If no original destination was stored, use the default server from the try list
    if (targetServer == null) {
      logger.debug("[TRANSFER] No original destination stored for {}, using try list", username);
      List<String> tryList = server.getConfiguration().getAttemptConnectionOrder();
      if (!tryList.isEmpty()) {
        String serverName = tryList.get(0);
        Optional<RegisteredServer> defaultServer = server.getServer(serverName);
        if (defaultServer.isPresent()) {
          targetServer = defaultServer.get();
          logger.debug("[TRANSFER] Using default server from try list for {}: {}", username, serverName);
        } else {
          logger.warn("[TRANSFER] Default server '{}' from try list not found for player {}", serverName, username);
        }
      } else {
        logger.warn("[TRANSFER] Try list is empty for player {}", username);
      }
    }
    
    // Still null? Try to use the fallback server
    if (targetServer == null) {
      logger.debug("[TRANSFER] Using fallback server for player {}", username);
      Optional<RegisteredServer> fallbackServer = server.getServer(MINIWORLD_FALLBACK_SERVER);
      if (fallbackServer.isPresent()) {
        targetServer = fallbackServer.get();
        logger.debug("[TRANSFER] Using fallback server for {}: {}", username, MINIWORLD_FALLBACK_SERVER);
      } else {
        logger.error("[TRANSFER] Could not find any suitable server to transfer player {} to (fallback '{}' not found)", 
            username, MINIWORLD_FALLBACK_SERVER);
        return;
      }
    }
    
    // Mark this transfer as pending
    pendingTransfers.add(playerId);
    logger.debug("[TRANSFER] Marked transfer as pending for player {}", username);
    
    // Clean up verification session
    MiniWorldSession session = miniWorldSessions.remove(playerId);
    if (session != null) {
      logger.debug("[TRANSFER] Cleaned up verification session for player {}", username);
    }
    
    // Transfer the player
    final RegisteredServer finalTarget = targetServer; // Need final for lambda
    String targetServerName = finalTarget.getServerInfo().getName();
    
    player.sendMessage(Component.text("Verification successful! Transferring you to the server...", 
        NamedTextColor.GREEN));
    
    logger.info("[TRANSFER] Sending verification success message to player {}", username);
    
    // A short delay before transfer makes the message visible
    PluginContainer plugin = server.getPluginManager().getPlugin("sentinalsproxy")
        .orElse(server.getPluginManager().getPlugin("velocity").orElse(null));
    
    if (plugin != null) {
      logger.debug("[TRANSFER] Scheduling transfer for player {} to {} in 500ms", username, targetServerName);
      
      server.getScheduler().buildTask(plugin, () -> {
        if (player.isActive()) {
          logger.info("[TRANSFER] Executing transfer for player {} to server {}", username, targetServerName);
          player.createConnectionRequest(finalTarget).fireAndForget();
        } else {
          logger.warn("[TRANSFER] Player {} no longer active, cancelling transfer to {}", username, targetServerName);
          // Remove from pending transfers since it won't complete
          pendingTransfers.remove(playerId);
        }
      }).delay(500, TimeUnit.MILLISECONDS).schedule();
    } else {
      logger.error("[TRANSFER] No plugin found to schedule transfer for player {}", username);
    }
  }
  
  /**
   * Updates the MiniWorldSession check logic to determine if a player has passed verification.
   */
  private void updateMiniWorldSessionCheck() {
    try {
      MiniWorldSession.class.getDeclaredMethod("isCheckPassed").setAccessible(true);
    } catch (NoSuchMethodException e) {
      logger.error("Failed to update MiniWorldSession check logic", e);
      // Continue execution - this is a reflection helper, and we can gracefully handle the failure
    }
  }
  
  /**
   * Process player movement in the mini-world.
   * 
   * @param player the player
   * @param x the x coordinate
   * @param y the y coordinate
   * @param z the z coordinate
   */
  public void processMiniWorldMovement(Player player, double x, double y, double z) {
    UUID playerId = player.getUniqueId();
    MiniWorldSession session = miniWorldSessions.get(playerId);
    
    if (session != null && !session.isCompleted()) {
      session.recordMovement(x, y, z);
      
      // Check if the session is now complete
      if (session.isCompleted()) {
        handleMiniWorldResult(player, session.isPassed());
      }
    }
  }
  
  /**
   * Process player interaction in the mini-world.
   * 
   * @param player the player
   */
  public void processMiniWorldInteraction(Player player) {
    UUID playerId = player.getUniqueId();
    MiniWorldSession session = miniWorldSessions.get(playerId);
    
    if (session != null && !session.isCompleted()) {
      session.recordInteraction();
      
      // Check if the session is now complete
      if (session.isCompleted()) {
        handleMiniWorldResult(player, session.isPassed());
      }
    }
  }
  
  /**
   * Handle the result of a mini-world check.
   * 
   * @param player the player
   * @param passed whether they passed the check
   */
  private void handleMiniWorldResult(Player player, boolean passed) {
    UUID playerId = player.getUniqueId();
    
    // Remove the session
    miniWorldSessions.remove(playerId);
    
    if (passed) {
      // Player passed - mark as verified
      verifiedPlayers.add(playerId);
      failedChecks.remove(playerId);
      
      // In a real implementation, teleport them back to their original position
      logger.info("Player {} passed mini-world check and has been verified", player.getUsername());
    } else {
      // Player failed - increment failed checks
      incrementFailedChecks(player);
      logger.info("Player {} failed mini-world check", player.getUsername());
    }
    
    // In a real implementation, here we would:
    // 1. Teleport them back to their original position if passed
    // 2. Take action (warning or kick) if failed
  }
  
  /**
   * Get the current mini-world session for a player.
   * 
   * @param playerId the player's UUID
   * @return the session or null if not in a mini-world check
   */
  public MiniWorldSession getMiniWorldSession(UUID playerId) {
    return miniWorldSessions.get(playerId);
  }
  
  /**
   * Check if a player is currently in a mini-world check.
   * 
   * @param playerId the player's UUID
   * @return true if they are in a mini-world check
   */
  public boolean isInMiniWorldCheck(UUID playerId) {
    return miniWorldSessions.containsKey(playerId);
  }
  
  /**
   * Creates a mini-world environment for verifying if a player is a bot.
   * This puts the player in a test environment and monitors their movements
   * and interactions to determine if they behave like a human or a bot.
   * 
   * @param player the player to check
   * @return a future that will complete with the check result
   */
  public CompletableFuture<Boolean> createMiniWorldCheck(Player player) {
    if (!enabled || !config.isMiniWorldCheckEnabled()) {
      return CompletableFuture.completedFuture(true);
    }
    
    UUID playerId = player.getUniqueId();
    
    // Skip for already verified players
    if (verifiedPlayers.contains(playerId)) {
      logger.debug("Player {} already verified, skipping mini-world check", playerId);
      return CompletableFuture.completedFuture(true);
    }
    
    // Create the result future
    CompletableFuture<Boolean> result = new CompletableFuture<>();
    
    // Get player position (would come from the connecting server in real implementation)
    // Here we use dummy coordinates since we don't have direct access
    double x = 0.0;
    double y = 64.0; // Default world height
    double z = 0.0;
    
    // Create a mini-world session for this player
    MiniWorldSession session = new MiniWorldSession(playerId, player.getUsername(), x, y, z);
    miniWorldSessions.put(playerId, session);
    
    // Schedule the end of the test
    PluginContainer plugin = server.getPluginManager().getPlugin("sentinalsproxy")
        .orElse(server.getPluginManager().getPlugin("velocity").orElse(null));
    
    if (plugin != null) {
      server.getScheduler().buildTask(plugin, () -> {
        // Complete the check if it hasn't been completed yet
        if (!result.isDone()) {
          boolean passed = session.isPassed();
          session.complete(passed);
          result.complete(passed);
        }
      }).delay(config.getMiniWorldDuration(), TimeUnit.SECONDS).schedule();
    }
    
    return result;
  }
  
  /**
   * Process player movement in a mini-world session with rotation data.
   * This should be called when players in a mini-world session move.
   * 
   * @param player the player
   * @param x the x coordinate
   * @param y the y coordinate
   * @param z the z coordinate
   * @param yaw the yaw rotation
   * @param pitch the pitch rotation
   */
  public void processMiniWorldMovementWithRotation(Player player, double x, double y, double z, float yaw, float pitch) {
    UUID playerId = player.getUniqueId();
    MiniWorldSession session = miniWorldSessions.get(playerId);
    
    if (session != null) {
      // Record movement with the existing method
      session.recordMovement(x, y, z);
    }
  }
  
  /**
   * Process player interaction in a mini-world session with a specific type.
   * This should be called when players in a mini-world session interact with something.
   * 
   * @param player the player
   * @param interactionType the type of interaction
   */
  public void processMiniWorldInteractionWithType(Player player, String interactionType) {
    UUID playerId = player.getUniqueId();
    MiniWorldSession session = miniWorldSessions.get(playerId);
    
    if (session != null) {
      // Record a generic interaction
      session.recordInteraction();
    }
  }
  
  /**
   * Class representing a mini-world environment check session.
   * This tracks a player's interaction with the virtual test environment.
   */
  public class MiniWorldSession {
    public final UUID playerId;
    public final String playerName;
    public final long startTime;
    public final double startX, startY, startZ;
    public double currentX, currentY, currentZ;
    private boolean completed = false;
    private boolean passed = false;
    public int movementCount = 0;
    public int interactionCount = 0;
    public boolean hasJumped = false;
    public boolean hasCrouched = false;
    public boolean hasInteracted = false;
    private final List<Vector3d> movementHistory = new ArrayList<>();
    private final List<Long> movementTimestamps = new ArrayList<>();
    private int mouseMoveCount = 0;
    private int keyPressCount = 0;
    
    // Constructor to initialize a new session
    public MiniWorldSession(UUID playerId, String playerName, double x, double y, double z) {
      this.playerId = playerId;
      this.playerName = playerName;
      this.startTime = System.currentTimeMillis();
      this.startX = x;
      this.startY = y;
      this.startZ = z;
      this.currentX = x;
      this.currentY = y;
      this.currentZ = z;
      
      // Initialize first movement record
      this.movementHistory.add(new Vector3d(x, y, z));
      this.movementTimestamps.add(System.currentTimeMillis());
    }
    
    // Record player movement in the mini-world
    public void recordMovement(double x, double y, double z) {
      // Calculate movement delta
      double deltaX = x - currentX;
      double deltaY = y - currentY;
      double deltaZ = z - currentZ;
      double movementDistance = Math.sqrt(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);
      
      // Only record significant movements to avoid spam
      if (movementDistance < 0.01) {
        return;
      }
      
      // Check if they jumped (y increased)
      if (y > currentY + 0.5) {
        hasJumped = true;
        logger.debug("[LOBBY-MOVEMENT] Player {} JUMPED in mini-world (Y: {:.2f} -> {:.2f})", 
            playerName, currentY, y);
      }
      
      // Check if they crouched (y decreased slightly)
      if (y < currentY - 0.1 && y > currentY - 0.5) {
        hasCrouched = true;
        logger.debug("[LOBBY-MOVEMENT] Player {} CROUCHED in mini-world (Y: {:.2f} -> {:.2f})", 
            playerName, currentY, y);
      }
      
      // Update position
      currentX = x;
      currentY = y;
      currentZ = z;
      movementCount++;
      
      // Record movement for analysis
      movementHistory.add(new Vector3d(x, y, z));
      movementTimestamps.add(System.currentTimeMillis());
      
      // Enhanced movement logging
      logger.debug("[LOBBY-MOVEMENT] Player {} moved in mini-world", playerName);
      logger.debug("[LOBBY-MOVEMENT]   Position: [{:.2f}, {:.2f}, {:.2f}]", x, y, z);
      logger.debug("[LOBBY-MOVEMENT]   Delta: [{:.2f}, {:.2f}, {:.2f}], Distance: {:.2f}", 
          deltaX, deltaY, deltaZ, movementDistance);
      logger.debug("[LOBBY-MOVEMENT]   Move count: {}, Total distance: {:.2f}", 
          movementCount, getTotalPathDistance());
      
      // Log patterns for bot detection
      if (movementCount > 1) {
        long timeSinceLastMove = System.currentTimeMillis() - movementTimestamps.get(movementTimestamps.size() - 2);
        logger.debug("[LOBBY-MOVEMENT]   Time since last move: {} ms", timeSinceLastMove);
        
        // Check for suspiciously consistent timing (common bot behavior)
        if (movementCount > 5) {
          boolean suspiciousTiming = checkForSuspiciousTiming();
          if (suspiciousTiming) {
            logger.warn("[LOBBY-MOVEMENT] Player {} showing suspicious movement timing patterns", playerName);
          }
        }
      }
    }
    
    // Record mouse movement (yaw/pitch changes)
    public void recordMouseMovement() {
      mouseMoveCount++;
    }
    
    // Record key press (movement keys, action keys)
    public void recordKeyPress() {
      keyPressCount++;
    }
    
    // Record player interaction in the mini-world
    public void recordInteraction() {
      interactionCount++;
      hasInteracted = true;
      
      long sessionDuration = System.currentTimeMillis() - startTime;
      
      logger.debug("[LOBBY-INTERACTION] Player {} interacted in mini-world", playerName);
      logger.debug("[LOBBY-INTERACTION]   Interaction count: {}", interactionCount);
      logger.debug("[LOBBY-INTERACTION]   Session duration: {} ms", sessionDuration);
      logger.debug("[LOBBY-INTERACTION]   Current verification score: {:.2f}", getCurrentVerificationScore());
      
      // Log first interaction milestone
      if (interactionCount == 1) {
        logger.info("[LOBBY-INTERACTION] Player {} performed first interaction after {} ms", 
            playerName, sessionDuration);
      }
    }
    
    // Calculate the distance moved from start
    public double getDistanceMoved() {
      double dx = currentX - startX;
      double dy = currentY - startY;
      double dz = currentZ - startZ;
      return Math.sqrt(dx * dx + dy * dy + dz * dz);
    }
    
    // Calculate the total path distance (not just straight line)
    public double getTotalPathDistance() {
      double totalDistance = 0;
      
      for (int i = 1; i < movementHistory.size(); i++) {
        Vector3d prev = movementHistory.get(i - 1);
        Vector3d current = movementHistory.get(i);
        
        double dx = current.getX() - prev.getX();
        double dy = current.getY() - prev.getY();
        double dz = current.getZ() - prev.getZ();
        
        totalDistance += Math.sqrt(dx * dx + dy * dy + dz * dz);
      }
      
      return totalDistance;
    }
    
    // Calculate movement pattern complexity (higher is more human-like)
    public double getMovementComplexity() {
      // A very simple complexity metric - real implementation would be more sophisticated
      if (movementHistory.size() < 5) {
        return 0;
      }
      
      // Count direction changes
      int directionChanges = 0;
      Vector3d prevDirection = null;
      
      for (int i = 1; i < movementHistory.size(); i++) {
        Vector3d prev = movementHistory.get(i - 1);
        Vector3d current = movementHistory.get(i);
        
        // Get movement direction
        Vector3d direction = new Vector3d(
            current.getX() - prev.getX(),
            current.getY() - prev.getY(),
            current.getZ() - prev.getZ()
        );
        
        // Skip if too small a movement
        double magnitude = Math.sqrt(direction.getX() * direction.getX() + 
                                    direction.getY() * direction.getY() + 
                                    direction.getZ() * direction.getZ());
        if (magnitude < 0.1) {
          continue;
        }
        
        if (prevDirection != null) {
          // Check if direction changed significantly
          double dotProduct = direction.getX() * prevDirection.getX() +
                              direction.getY() * prevDirection.getY() +
                              direction.getZ() * prevDirection.getZ();
          double dirMagnitude = magnitude * Math.sqrt(
              prevDirection.getX() * prevDirection.getX() +
              prevDirection.getY() * prevDirection.getY() +
              prevDirection.getZ() * prevDirection.getZ()
          );
          
          // Normalized dot product < 0.7 means direction changed by > ~45 degrees
          if (dirMagnitude > 0 && dotProduct / dirMagnitude < 0.7) {
            directionChanges++;
          }
        }
        
        prevDirection = direction;
      }
      
      return directionChanges * 1.5 + (hasJumped ? 2 : 0) + (hasCrouched ? 2 : 0) + interactionCount * 3;
    }
    
    // Check for natural timing between movements (bots often have too consistent timing)
    public boolean hasNaturalTiming() {
      if (movementTimestamps.size() < 5) {
        return false;
      }
      
      // Calculate timing variability
      long[] intervals = new long[movementTimestamps.size() - 1];
      for (int i = 0; i < intervals.length; i++) {
        intervals[i] = movementTimestamps.get(i + 1) - movementTimestamps.get(i);
      }
      
      // Calculate mean and standard deviation
      double mean = 0;
      for (long interval : intervals) {
        mean += interval;
      }
      mean /= intervals.length;
      
      double variance = 0;
      for (long interval : intervals) {
        variance += Math.pow(interval - mean, 2);
      }
      variance /= intervals.length;
      double stdDev = Math.sqrt(variance);
      
      // Coefficient of variation - higher means more human-like variability
      double cv = stdDev / mean;
      
      // Humans typically have more variable timing than bots
      return cv > 0.3;
    }
    
    // Check if the session has timed out
    public boolean isTimedOut() {
      return System.currentTimeMillis() - startTime > config.getMiniWorldDuration() * 1000;
    }
    
    // Check if the player has been in the mini-world long enough
    public boolean hasMinimumTime() {
      return System.currentTimeMillis() - startTime >= 5000; // At least 5 seconds
    }
    
    // Check if the player has passed the verification check
    public boolean isCheckPassed() {
      // The basic checks
      boolean enoughMovements = movementCount >= config.getMiniWorldMinMovements();
      boolean movedFarEnough = getDistanceMoved() >= config.getMiniWorldMinDistance();
      boolean hasEnoughInteraction = hasInteracted || (hasJumped && hasCrouched);
      
      // Advanced human-like behavior checks
      boolean hasComplexMovement = getMovementComplexity() >= 5;
      boolean hasVariableTiming = hasNaturalTiming();
      boolean hasEnoughMouseMovement = mouseMoveCount >= 5;
      
      // For now, we'll use a simple scoring system
      int score = 0;
      if (enoughMovements) score += 2;
      if (movedFarEnough) score += 2;
      if (hasEnoughInteraction) score += 3;
      if (hasJumped) score += 1;
      if (hasCrouched) score += 1;
      if (hasComplexMovement) score += 3;
      if (hasVariableTiming) score += 2;
      if (hasEnoughMouseMovement) score += 1;
      
      // Log the verification details
      logger.debug("Player {} verification score: {}/15", playerName, score);
      logger.debug("  Movements: {}, Distance: {}, Interactions: {}", 
          movementCount, String.format("%.2f", getDistanceMoved()), interactionCount);
      logger.debug("  Jumped: {}, Crouched: {}, Complexity: {}, Natural timing: {}", 
          hasJumped, hasCrouched, String.format("%.2f", getMovementComplexity()), hasVariableTiming);
      
      // Need at least 7 points to pass (can tweak as needed)
      return score >= 7;
    }
    
    // Evaluate whether the player passes the mini-world check
    private void evaluateSession() {
      if (completed) {
        return; // Already evaluated
      }
      
      if (isTimedOut()) {
        // Session timed out - fail
        completed = true;
        passed = false;
        logger.info("Player {} failed mini-world check: timed out", playerName);
        return;
      }
      
      // Auto-complete if we have enough data
      if (hasMinimumTime() && movementCount >= 15 && interactionCount >= 3 && hasJumped && hasCrouched) {
        completed = true;
        passed = true;
        logger.info("Player {} passed mini-world check early: strong human indicators detected", playerName);
      }
    }
    
    // Mark the session as complete (for timeout or other reasons)
    public void complete(boolean pass) {
      if (!completed) {
        completed = true;
        passed = pass;
        logger.info("Player {} mini-world check marked complete. Result: {}", 
            playerName, passed ? "PASS" : "FAIL");
      }
    }
    
    // Get the time elapsed in seconds
    public int getElapsedSeconds() {
      return (int)((System.currentTimeMillis() - startTime) / 1000);
    }
    
    // Get time remaining in seconds
    public int getTimeRemainingSeconds() {
      int totalDuration = config.getMiniWorldDuration();
      int elapsed = getElapsedSeconds();
      return Math.max(0, totalDuration - elapsed);
    }
    
    // Check if the session is complete
    public boolean isCompleted() {
      return completed;
    }
    
    // Check if the player passed the check
    public boolean isPassed() {
      return passed;
    }
    
    // Get status message for player
    public Component getStatusMessage() {
      int timeRemaining = getTimeRemainingSeconds();
      
      return Component.text("Verification Status: ", NamedTextColor.GOLD)
          .append(Component.text(timeRemaining + " seconds remaining", NamedTextColor.YELLOW))
          .append(Component.newline())
          .append(Component.text("Movements: ", NamedTextColor.GRAY))
          .append(Component.text(movementCount, 
              movementCount >= config.getMiniWorldMinMovements() ? NamedTextColor.GREEN : NamedTextColor.RED))
          .append(Component.text(" | Distance: ", NamedTextColor.GRAY))
          .append(Component.text(String.format("%.1f", getDistanceMoved()), 
              getDistanceMoved() >= config.getMiniWorldMinDistance() ? NamedTextColor.GREEN : NamedTextColor.RED))
          .append(Component.text(" | Interactions: ", NamedTextColor.GRAY))
          .append(Component.text(interactionCount, 
              interactionCount > 0 ? NamedTextColor.GREEN : NamedTextColor.RED));
    }
    
    /**
     * Check for suspicious timing patterns in movement.
     * Inspired by Sonar's bot detection approach.
     * 
     * @return true if suspicious timing is detected
     */
    private boolean checkForSuspiciousTiming() {
      if (movementTimestamps.size() < 6) {
        return false;
      }
      
      // Get last 5 intervals
      long[] intervals = new long[5];
      for (int i = 0; i < 5; i++) {
        int idx = movementTimestamps.size() - 6 + i;
        intervals[i] = movementTimestamps.get(idx + 1) - movementTimestamps.get(idx);
      }
      
      // Check for too consistent timing (bot-like behavior)
      long avgInterval = 0;
      for (long interval : intervals) {
        avgInterval += interval;
      }
      avgInterval /= intervals.length;
      
      // Count intervals within 10ms of average
      int consistentCount = 0;
      for (long interval : intervals) {
        if (Math.abs(interval - avgInterval) <= 10) {
          consistentCount++;
        }
      }
      
      // If 4/5 intervals are extremely consistent, it's suspicious
      return consistentCount >= 4 && avgInterval > 0 && avgInterval < 200;
    }
    
    /**
     * Calculate current verification score based on multiple factors.
     * Higher score = more likely to be human.
     * 
     * @return verification score
     */
    private double getCurrentVerificationScore() {
      double score = 0.0;
      
      // Movement score (0-3 points)
      if (movementCount >= MINIWORLD_MIN_MOVEMENTS) {
        score += 1.0;
      }
      score += Math.min(2.0, movementCount / 10.0);
      
      // Distance score (0-2 points)
      double distance = getDistanceMoved();
      if (distance >= MINIWORLD_MIN_DISTANCE) {
        score += 1.0;
      }
      score += Math.min(1.0, distance / 10.0);
      
      // Interaction score (0-2 points)
      if (hasInteracted) {
        score += 1.0;
      }
      score += Math.min(1.0, interactionCount / 3.0);
      
      // Movement complexity score (0-2 points)
      double complexity = getMovementComplexity();
      score += Math.min(2.0, complexity / 10.0);
      
      // Natural timing bonus (0-1 points)
      if (hasNaturalTiming()) {
        score += 1.0;
      }
      
      // Action variety bonus (0-2 points)
      int varietyCount = 0;
      if (hasJumped) varietyCount++;
      if (hasCrouched) varietyCount++;
      if (hasInteracted) varietyCount++;
      if (mouseMoveCount > 5) varietyCount++;
      if (keyPressCount > 10) varietyCount++;
      
      score += varietyCount * 0.4;
      
      return score;
    }
  }
  
  /**
   * Class to track player state for anti-bot verification.
   */
  private static class PlayerState {
    private final UUID playerId;
    private final InetAddress address;
    private Vector3d lastPosition;
    private Vector3d currentPosition;
    private float lastYaw;
    private float currentYaw;
    private float lastPitch;
    private float currentPitch;
    private boolean onGround;
    private long firstJoinTime;
    private long lastMoveTime;
    private long lastUpdateTime;
    private int moveCount;
    private int yawViolations;
    private int gravityViolations;
    private int hitboxViolations;
    private int interactionCount;
    private long lastPositiveYVelocity;
    private String clientBrand;
    private final long[] rotationTimestamps = new long[10];
    private final float[] rotationValues = new float[10];
    private int rotationIndex = 0;
    
    public PlayerState() {
      this(null, null);
    }
    
    public PlayerState(UUID playerId, InetAddress address) {
      this.playerId = playerId;
      this.address = address;
      this.firstJoinTime = System.currentTimeMillis();
      this.lastMoveTime = System.currentTimeMillis();
      this.lastUpdateTime = System.currentTimeMillis();
      this.moveCount = 0;
      this.yawViolations = 0;
      this.gravityViolations = 0;
      this.hitboxViolations = 0;
      this.interactionCount = 0;
      this.lastPositiveYVelocity = System.currentTimeMillis();
      this.lastPosition = new Vector3d(0, 0, 0);
      this.currentPosition = new Vector3d(0, 0, 0);
    }
    
    public boolean isFirstMove() {
      return moveCount <= 1;
    }
    
    public void updatePosition(double x, double y, double z, float yaw, float pitch, boolean onGround) {
      this.lastPosition = this.currentPosition;
      this.currentPosition = new Vector3d(x, y, z);
      this.lastYaw = this.currentYaw;
      this.currentYaw = yaw;
      this.lastPitch = this.currentPitch;
      this.currentPitch = pitch;
      this.onGround = onGround;
      this.lastMoveTime = System.currentTimeMillis();
      this.moveCount++;
      
      // Track if player is moving upward (positive Y velocity)
      if (this.currentPosition.getY() > this.lastPosition.getY()) {
        this.lastPositiveYVelocity = System.currentTimeMillis();
      }
    }
    
    public Vector3d getLastPosition() {
      return lastPosition;
    }
    
    public Vector3d getCurrentPosition() {
      return currentPosition;
    }
    
    public float getLastYaw() {
      return lastYaw;
    }
    
    public float getCurrentYaw() {
      return currentYaw;
    }
    
    public float getLastPitch() {
      return lastPitch;
    }
    
    public float getCurrentPitch() {
      return currentPitch;
    }
    
    public boolean isOnGround() {
      return onGround;
    }
    
    public long getFirstJoinTime() {
      return firstJoinTime;
    }
    
    public long getLastMoveTime() {
      return lastMoveTime;
    }
    
    public int getMoveCount() {
      return moveCount;
    }
    
    public int getYawViolations() {
      return yawViolations;
    }
    
    public void incrementYawViolations() {
      this.yawViolations++;
    }
    
    public void resetYawViolations() {
      this.yawViolations = 0;
    }
    
    public void incrementGravityViolations() {
      this.gravityViolations++;
    }
    
    public void resetGravityViolation() {
      this.gravityViolations = 0;
    }
    
    public int getGravityViolations() {
      return gravityViolations;
    }
    
    public void incrementHitboxViolations() {
      this.hitboxViolations++;
    }
    
    public int getHitboxViolations() {
      return hitboxViolations;
    }
    
    public double getSecondsSincePositiveYVelocity() {
      return (System.currentTimeMillis() - lastPositiveYVelocity) / 1000.0;
    }
    
    public void incrementInteractionCount() {
      this.interactionCount++;
      this.lastUpdateTime = System.currentTimeMillis();
    }
    
    public int getInteractionCount() {
      return interactionCount;
    }
    
    public long getLastUpdateTime() {
      return lastUpdateTime;
    }
    
    public long getTimeSinceConnection() {
      return (System.currentTimeMillis() - firstJoinTime) / 1000;
    }
    
    public boolean hasEnoughData() {
      return moveCount >= 5;
    }
    
    public String getClientBrand() {
      return clientBrand;
    }
    
    public void setClientBrand(String clientBrand) {
      this.clientBrand = clientBrand;
      this.lastUpdateTime = System.currentTimeMillis();
    }
    
    public void updatePositionAndRotation(double x, double y, double z, float yaw, float pitch) {
      updatePosition(x, y, z, yaw, pitch, false);
      
      // Record rotation for pattern detection
      rotationTimestamps[rotationIndex] = System.currentTimeMillis();
      rotationValues[rotationIndex] = yaw;
      rotationIndex = (rotationIndex + 1) % rotationValues.length;
    }
    
    public boolean hasRepeatedRotationPattern() {
      // If we don't have enough data yet
      if (moveCount < rotationValues.length) {
        return false;
      }
      
      // Check for identical rotation values (bot-like behavior)
      float firstValue = rotationValues[0];
      int identicalCount = 1;
      
      for (int i = 1; i < rotationValues.length; i++) {
        if (Math.abs(rotationValues[i] - firstValue) < 0.1f) {
          identicalCount++;
        }
      }
      
      // If more than 70% are identical, suspicious
      return identicalCount > (rotationValues.length * 0.7);
    }
  }
  
  /**
   * Get all active mini-world sessions.
   * 
   * @return map of active mini-world sessions
   */
  public Map<UUID, MiniWorldSession> getMiniWorldSessions() {
    return miniWorldSessions;
  }
  
  /**
   * Get the set of verified players.
   * 
   * @return set of verified player UUIDs
   */
  public Set<UUID> getVerifiedPlayers() {
    return verifiedPlayers;
  }
  
  /**
   * Check if an IP is exceeding connection rate limits.
   * 
   * @param address the IP address to check
   * @return true if the connection rate is acceptable, false if it exceeds limits
   */
  public boolean checkConnectionRate(InetAddress address) {
    if (!config.isConnectionRateLimitEnabled()) {
      return true;
    }
    
    // Get the timestamps of recent connections from this IP
    List<Long> connectionTimes = connectionTimestampsByIp.computeIfAbsent(
        address, k -> new ArrayList<>());
    
    // Remove timestamps older than the configured window
    long now = System.currentTimeMillis();
    long windowStart = now - config.getConnectionRateWindowMs();
    connectionTimes.removeIf(timestamp -> timestamp < windowStart);
    
    // Add the current timestamp
    connectionTimes.add(now);
    
    // Check if the number of connections in the window exceeds the limit
    if (connectionTimes.size() > config.getConnectionRateLimit()) {
      // Connection rate exceeded, throttle this IP
      throttledIps.add(address);
      logger.warn("Connection rate limit exceeded for IP: {} ({} connections in {} ms)", 
          address.getHostAddress(), connectionTimes.size(), config.getConnectionRateWindowMs());
      return false;
    }
    
    return true;
  }
  
  /**
   * Check if a username matches known bot-like patterns.
   * 
   * @param username the username to check
   * @return true if the username is acceptable, false if it matches bot patterns
   */
  public boolean checkUsernamePattern(String username) {
    if (!config.isUsernamePatternCheckEnabled()) {
      return true;
    }
    
    logger.debug("[AntiBot] Checking username pattern for: {}", username);
    
    // Allow legitimate usernames - common names and reasonable patterns
    if (isLegitimateUsername(username)) {
      logger.debug("[AntiBot] Username '{}' is in legitimate whitelist", username);
      return true;
    }
    
    // Look for common bot username patterns
    
    // 1. Random character sequences (e.g., asdf1234, but exclude normal names)
    if (username.matches("^[a-z0-9]{8}$") && !username.matches(".*[aeiou].*")) {
      logger.warn("[AntiBot] Username '{}' matches random character pattern", username);
      incrementPatternCount(username);
      return false;
    }
    
    // 2. Numbered accounts with MANY numbers (e.g., Player12345, User98765)
    // Only flag if there are 3+ consecutive digits, not just any numbers
    if (username.matches("^[A-Za-z]+\\d{3,}$")) {
      String prefix = username.replaceAll("\\d+$", "");
      logger.debug("[AntiBot] Checking numbered pattern for prefix '{}' from username '{}'", prefix, username);
      if (usernamePatternCounts.getOrDefault(prefix, 0) > config.getUsernamePatternThreshold()) {
        logger.warn("[AntiBot] Username '{}' exceeds pattern threshold for prefix '{}'", username, prefix);
        return false;
      }
      incrementPatternCount(prefix);
    }
    
    // 3. Check for sequential usernames with fixed format (4+ consecutive digits)
    if (username.length() >= 5 && username.matches(".*\\d{4,}.*")) {
      String pattern = username.replaceAll("\\d{4,}", "XXXX");
      logger.debug("[AntiBot] Checking sequential pattern '{}' from username '{}'", pattern, username);
      if (usernamePatternCounts.getOrDefault(pattern, 0) > config.getUsernamePatternThreshold()) {
        logger.warn("[AntiBot] Username '{}' exceeds pattern threshold for pattern '{}'", username, pattern);
        return false;
      }
      incrementPatternCount(pattern);
    }
    
    // 4. Check for obvious bot patterns
    if (username.toLowerCase().contains("bot") || 
        username.toLowerCase().contains("test") ||
        username.toLowerCase().matches(".*x{3,}.*") ||
        username.toLowerCase().matches(".*z{3,}.*")) {
      logger.warn("[AntiBot] Username '{}' contains obvious bot patterns", username);
      return false;
    }
    
    logger.debug("[AntiBot] Username '{}' passed all pattern checks", username);
    return true;
  }
  
  /**
   * Increment the count for a detected username pattern.
   * 
   * @param pattern the pattern to track
   */
  private void incrementPatternCount(String pattern) {
    usernamePatternCounts.compute(pattern, (k, v) -> (v == null) ? 1 : v + 1);
  }
  
  /**
   * Check if an IP address has been throttled due to excessive connection attempts.
   * 
   * @param address the IP address to check
   * @return true if the IP is throttled
   */
  public boolean isIpThrottled(InetAddress address) {
    return throttledIps.contains(address);
  }
  
  /**
   * Check connection latency.
   * 
   * @param address the IP address to check
   * @param latencyMs the measured latency in milliseconds
   * @return true if latency is acceptable, false if it exceeds limits
   */
  public boolean checkLatency(InetAddress address, long latencyMs) {
    if (!config.isLatencyCheckEnabled()) {
      return true;
    }
    
    // Store the latency for this IP
    latencyByIp.put(address, latencyMs);
    
    // Check if latency exceeds the configured threshold
    if (latencyMs > config.getMaxLatencyMs()) {
      logger.debug("High latency detected for IP {}: {} ms (max: {} ms)", 
          address.getHostAddress(), latencyMs, config.getMaxLatencyMs());
      return false;
    }
    
    return true;
  }
  
  /**
   * Check if the connection came through a domain or direct IP.
   * 
   * @param address the IP address to check
   * @param hostname the hostname used to connect, if available
   * @return true if the connection is acceptable, false if it fails the DNS check
   */
  public boolean checkDnsResolution(InetAddress address, String hostname) {
    if (!config.isDnsCheckEnabled() || hostname == null || hostname.isEmpty()) {
      return true;
    }
    
    // Cache the hostname for this IP
    dnsResolveCache.put(address, hostname);
    
    // If direct IP connections are not allowed, check if the hostname is an IP
    if (!config.isAllowDirectIpConnections() && hostname.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
      logger.debug("Direct IP connection detected from {}", hostname);
      return false;
    }
    
    // If the hostname is not in the allowed domains list, reject
    if (!config.getAllowedDomains().isEmpty() && 
        config.getAllowedDomains().stream().noneMatch(domain -> hostname.endsWith(domain))) {
      logger.debug("Hostname {} not in allowed domains list", hostname);
      return false;
    }
    
    return true;
  }
  
  public void onPlayerLogin(ConnectedPlayer player) {
    if (!enabled || config.isExcluded(player.getRemoteAddress().getHostString())) {
      return;
    }
    
    InetAddress address = player.getRemoteAddress().getAddress();
    String username = player.getUsername();
    UUID playerId = player.getUniqueId();
    
    // Track this login attempt
    connectionsByIp.computeIfAbsent(address, k -> new AtomicInteger()).incrementAndGet();
    connectionsByUsername.computeIfAbsent(username, k -> new AtomicInteger()).incrementAndGet();
    
    // Track connection timestamps for rate limiting
    List<Long> timestamps = connectionTimestampsByIp
        .computeIfAbsent(address, k -> new ArrayList<>());
    synchronized (timestamps) {
      long now = System.currentTimeMillis();
      timestamps.add(now);
      // Remove timestamps older than the rate limiting window
      timestamps.removeIf(time -> now - time > config.getRateLimitWindowMillis());
    }
    
    int failedCheckCount = 0;
    
    // Rate limiting check
    if (config.isRateLimitEnabled()) {
      List<Long> recentConnections = connectionTimestampsByIp.get(address);
      if (recentConnections != null && recentConnections.size() > config.getRateLimitThreshold()) {
        logger.info("Player {} failed rate limit check: {} connections in {} ms",
            username, recentConnections.size(), config.getRateLimitWindowMillis());
        failedCheckCount++;
        suspiciousPlayers.add(playerId);
      }
    }
    
    // Username pattern check
    if (config.isPatternCheckEnabled()) {
      if (isUsernameMatchingPatterns(username)) {
        logger.info("Player {} failed username pattern check", username);
        failedCheckCount++;
        suspiciousPlayers.add(playerId);
      }
    }
    
    // DNS check
    if (config.isDnsCheckEnabled()) {
      if (!isAddressResolvable(address, username)) {
        logger.info("Player {} failed DNS check", username);
        failedCheckCount++;
        suspiciousPlayers.add(playerId);
      }
    }
    
    // Latency check
    if (config.isLatencyCheckEnabled()) {
      long ping = player.getPing();
      latencyByIp.put(address, ping);
      if (ping < config.getMinLatencyThreshold() || ping > config.getMaxLatencyThreshold()) {
        logger.info("Player {} failed latency check: {} ms (outside range: {} - {})",
            username, ping, config.getMinLatencyThreshold(), config.getMaxLatencyThreshold());
        failedCheckCount++;
        suspiciousPlayers.add(playerId);
      }
    }

    // Original gravity, rotation, hitbox and client-brand checks
    playerStates.put(playerId, new PlayerState());

    // Save the failed check count
    if (failedCheckCount > 0) {
      failedChecks.put(playerId, failedCheckCount);
      
      // If exceeded threshold, take action
      if (failedCheckCount >= kickThreshold) {
        player.disconnect(Component.text(config.getKickMessage()));
        logger.info("Player {} was kicked due to failing {} anti-bot checks",
            username, failedCheckCount);
      }
    }
  }
  
  /**
   * Checks if a username matches known bot patterns.
   *
   * @param username The username to check
   * @return true if the username matches a suspicious pattern
   */
  private boolean isUsernameMatchingPatterns(String username) {
    // Check against configured regex patterns
    for (String pattern : config.getUsernamePatterns()) {
      if (username.matches(pattern)) {
        return true;
      }
    }
    
    // Check for sequential characters (e.g., "abcdef", "123456")
    if (config.isSequentialCharCheck() && hasSequentialChars(username, config.getSequentialCharThreshold())) {
      return true;
    }
    
    // Check for random character distribution
    if (config.isRandomDistributionCheck() && hasRandomDistribution(username)) {
      return true;
    }
    
    return false;
  }
  
  /**
   * Checks if a string has sequential characters.
   *
   * @param str The string to check
   * @param threshold The minimum length of sequential characters to be considered suspicious
   * @return true if the string has sequential characters exceeding the threshold
   */
  private boolean hasSequentialChars(String str, int threshold) {
    if (str.length() < threshold) {
      return false;
    }
    
    int sequentialCount = 1;
    for (int i = 1; i < str.length(); i++) {
      if (str.charAt(i) == str.charAt(i - 1) + 1 || 
          (Character.isDigit(str.charAt(i)) && Character.isDigit(str.charAt(i - 1)) && 
           str.charAt(i) == str.charAt(i - 1) + 1)) {
        sequentialCount++;
        if (sequentialCount >= threshold) {
          return true;
        }
      } else {
        sequentialCount = 1;
      }
    }
    
    return false;
  }
  
  /**
   * Checks if a string appears to have a random distribution of characters.
   *
   * @param str The string to check
   * @return true if the string has random distribution characteristics
   */
  private boolean hasRandomDistribution(String str) {
    if (str.length() < 8) {
      return false;
    }
    
    // Count character types
    int lowercase = 0;
    int uppercase = 0;
    int digits = 0;
    int special = 0;
    
    for (char c : str.toCharArray()) {
      if (Character.isLowerCase(c)) lowercase++;
      else if (Character.isUpperCase(c)) uppercase++;
      else if (Character.isDigit(c)) digits++;
      else special++;
    }
    
    // If it has a very even distribution of character types, it might be random
    double total = str.length();
    double lowercaseRatio = lowercase / total;
    double uppercaseRatio = uppercase / total;
    double digitsRatio = digits / total;
    double specialRatio = special / total;
    
    // If each character type represents between 15% and 35% of the string
    return (lowercaseRatio > 0.15 && lowercaseRatio < 0.35 &&
            uppercaseRatio > 0.15 && uppercaseRatio < 0.35 &&
            digitsRatio > 0.15 && digitsRatio < 0.35) ||
           (special > 0 && specialRatio > 0.1); // Special chars are less common, so lower threshold
  }
  
  /**
   * Checks if an IP address can be resolved via reverse DNS.
   *
   * @param address The IP address to check
   * @param username The username associated with this check (for logging)
   * @return true if the address can be resolved
   */
  private boolean isAddressResolvable(InetAddress address, String username) {
    // Skip if already verified
    if (resolvedAddresses.contains(address)) {
      return true;
    }
    
    // Skip DNS check for local addresses
    if (address.isLoopbackAddress() || address.isSiteLocalAddress()) {
      resolvedAddresses.add(address);
      return true;
    }
    
    try {
      String hostName = address.getHostName();
      // If hostName equals the textual representation of the IP, it means resolution failed
      if (!hostName.equals(address.getHostAddress())) {
        resolvedAddresses.add(address);
        return true;
      }
      return false;
    } catch (Exception e) {
      logger.warn("DNS resolution check failed for player {}: {}", username, e.getMessage());
      // In case of resolution failure, let it pass to avoid false positives
      return true;
    }
  }
  
  /**
   * Updates the cleanup routine to handle the new data structures.
   */
  public void doCleanup() {
    long now = System.currentTimeMillis();
    long cleanupThreshold = now - TimeUnit.MINUTES.toMillis(config.getCleanupThresholdMinutes());
    
    // Clean up original data structures
    // ...
    
    // Clean up new data structures
    connectionTimestampsByIp.forEach((ip, timestamps) -> {
      synchronized (timestamps) {
        timestamps.removeIf(timestamp -> timestamp < cleanupThreshold);
      }
      if (timestamps.isEmpty()) {
        connectionTimestampsByIp.remove(ip);
      }
    });
    
    // Clean up latency data for IPs that haven't connected recently
    Iterator<Map.Entry<InetAddress, Long>> latencyIterator = latencyByIp.entrySet().iterator();
    while (latencyIterator.hasNext()) {
      InetAddress ip = latencyIterator.next().getKey();
      if (!connectionTimestampsByIp.containsKey(ip)) {
        latencyIterator.remove();
      }
    }
    
    // Reset connection counters for IPs that haven't connected recently
    Iterator<Map.Entry<InetAddress, AtomicInteger>> connectionIterator = connectionsByIp.entrySet().iterator();
    while (connectionIterator.hasNext()) {
      InetAddress ip = connectionIterator.next().getKey();
      if (!connectionTimestampsByIp.containsKey(ip)) {
        connectionIterator.remove();
      }
    }
    
    // Clean up username connection tracking
    connectionsByUsername.values().removeIf(count -> count.get() <= 0);
  }
  
  /**
   * Determines the initial server a player should connect to based on configuration.
   * Takes into account forced hosts and the default "try" list.
   * 
   * @param player the connecting player
   * @return the registered server the player should initially connect to
   */
  private Optional<RegisteredServer> determineInitialServer(Player player) {
    // Check for forced host first
    Optional<String> virtualHost = player.getVirtualHost().map(InetSocketAddress::getHostName);
    
    if (virtualHost.isPresent()) {
      String hostname = virtualHost.get();
      List<String> forcedServers = server.getConfiguration().getForcedHosts().get(hostname);
      
      if (forcedServers != null && !forcedServers.isEmpty()) {
        // Use the first server in the forced host list
        String serverName = forcedServers.get(0);
        logger.debug("Player {} connecting via forced host {} to server {}", 
            player.getUsername(), hostname, serverName);
        return server.getServer(serverName);
      }
    }
    
    // If no forced host applies, use the default try list
    List<String> tryList = server.getConfiguration().getAttemptConnectionOrder();
    if (!tryList.isEmpty()) {
      String serverName = tryList.get(0);
      logger.debug("Player {} connecting using try list to server {}", 
          player.getUsername(), serverName);
      return server.getServer(serverName);
    }
    
    logger.warn("No suitable initial server found for player {}", player.getUsername());
    return Optional.empty();
  }
  
  /**
   * Check if a username appears to be legitimate and should be whitelisted.
   * 
   * @param username the username to check
   * @return true if the username appears legitimate
   */
  private boolean isLegitimateUsername(String username) {
    // Length checks - legitimate usernames are typically 3-16 characters
    if (username.length() < 3 || username.length() > 16) {
      return false;
    }
    
    // Contains vowels (most real names have vowels)
    if (username.toLowerCase().matches(".*[aeiou].*")) {
      // If it contains vowels and is reasonable length, it's likely legitimate
      // Also check it's not just random letters with vowels
      if (username.length() >= 4 && username.length() <= 12) {
        // Allow names with up to 2 digits at the end (like "john123" or "mary05")
        if (username.matches("^[A-Za-z]+\\d{0,2}$")) {
          return true;
        }
        // Allow names with no numbers
        if (username.matches("^[A-Za-z]+$")) {
          return true;
        }
      }
    }
    
    // Common legitimate patterns
    String lower = username.toLowerCase();
    
    // Real names or name-like patterns
    if (lower.matches("^[a-z]{4,10}[a-z]{2,6}$") && lower.matches(".*[aeiou].*")) {
      return true;
    }
    
    // Allow underscores in reasonable positions
    if (username.matches("^[A-Za-z]+_[A-Za-z]+\\d{0,2}$")) {
      return true;
    }
    
    return false;
  }
}
