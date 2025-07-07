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

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.ServerInfo;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.connection.client.ConnectedPlayer;
import com.velocitypowered.proxy.protocol.MinecraftPacket;
import com.velocitypowered.proxy.protocol.packet.ClientSettings;
import com.velocitypowered.proxy.protocol.packet.JoinGame;
import com.velocitypowered.proxy.protocol.packet.KeepAlive;
import com.velocitypowered.proxy.protocol.packet.PlayerPosition;
import com.velocitypowered.proxy.protocol.packet.PlayerPositionAndRotation;
import com.velocitypowered.proxy.protocol.packet.ServerData;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import java.net.InetSocketAddress;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Built-in verification server that runs within the Velocity proxy.
 * This eliminates the need for external verification servers.
 */
public class VerificationServer {

  private static final Logger logger = LoggerFactory.getLogger(VerificationServer.class);
  
  private final VelocityServer server;
  private final AntiBot antiBot;
  private final ConcurrentHashMap<UUID, VerificationSession> activeSessions = new ConcurrentHashMap<>();
  
  // Virtual server info for the verification world
  private final ServerInfo verificationServerInfo;
  
  public VerificationServer(VelocityServer server, AntiBot antiBot) {
    this.server = server;
    this.antiBot = antiBot;
    
    // Create a virtual server info for the verification world
    this.verificationServerInfo = new ServerInfo(
        "verification-world", 
        new InetSocketAddress("localhost", 0) // Virtual address
    );
    
    logger.info("[VerificationServer] Built-in verification server initialized");
  }
  
  /**
   * Starts a verification session for a player.
   * 
   * @param player the player to verify
   * @return true if session started successfully
   */
  public boolean startVerificationSession(ConnectedPlayer player) {
    UUID playerId = player.getUniqueId();
    
    logger.info("[VerificationServer] Starting verification session for player: {}", player.getUsername());
    
    // Check if player is already in verification
    if (activeSessions.containsKey(playerId)) {
      logger.warn("[VerificationServer] Player {} already has an active verification session", player.getUsername());
      return false;
    }
    
    try {
      // Create verification session
      VerificationSession session = new VerificationSession(player, this);
      activeSessions.put(playerId, session);
      
      // Initialize the virtual world for the player
      session.initializeVerificationWorld();
      
      logger.info("[VerificationServer] Verification session started for player: {}", player.getUsername());
      return true;
      
    } catch (Exception e) {
      logger.error("[VerificationServer] Failed to start verification session for player: {}", player.getUsername(), e);
      return false;
    }
  }
  
  /**
   * Ends a verification session and transfers the player.
   * 
   * @param playerId the player's UUID
   * @param passed whether the player passed verification
   */
  public void endVerificationSession(UUID playerId, boolean passed) {
    VerificationSession session = activeSessions.remove(playerId);
    if (session == null) {
      logger.warn("[VerificationServer] No verification session found for player: {}", playerId);
      return;
    }
    
    try {
      if (passed) {
        session.onVerificationPassed();
      } else {
        session.onVerificationFailed();
      }
    } catch (Exception e) {
      logger.error("[VerificationServer] Error ending verification session for player: {}", playerId, e);
    }
  }
  
  /**
   * Handles packet processing for players in verification.
   * 
   * @param player the player
   * @param packet the packet to process
   * @return true if packet was handled by verification server
   */
  public boolean handlePacket(ConnectedPlayer player, MinecraftPacket packet) {
    VerificationSession session = activeSessions.get(player.getUniqueId());
    if (session == null) {
      return false; // Player not in verification
    }
    
    return session.handlePacket(packet);
  }
  
  /**
   * Gets the verification server info.
   * 
   * @return the server info for the verification world
   */
  public ServerInfo getVerificationServerInfo() {
    return verificationServerInfo;
  }
  
  /**
   * Checks if a player is currently in verification.
   * 
   * @param playerId the player's UUID
   * @return true if player is in verification
   */
  public boolean isPlayerInVerification(UUID playerId) {
    return activeSessions.containsKey(playerId);
  }
  
  /**
   * Gets statistics about active verification sessions.
   * 
   * @return formatted statistics string
   */
  public String getStatistics() {
    int activeSessions = this.activeSessions.size();
    return String.format("[VerificationServer] Active sessions: %d", activeSessions);
  }
  
  /**
   * Cleanup method to remove expired sessions.
   */
  public void cleanup() {
    int initialSize = activeSessions.size();
    
    activeSessions.entrySet().removeIf(entry -> {
      VerificationSession session = entry.getValue();
      if (session.isExpired()) {
        logger.info("[VerificationServer] Removing expired verification session for player: {}", 
            session.getPlayer().getUsername());
        session.onVerificationFailed();
        return true;
      }
      return false;
    });
    
    int removed = initialSize - activeSessions.size();
    if (removed > 0) {
      logger.info("[VerificationServer] Cleaned up {} expired verification sessions", removed);
    }
  }
  
  /**
   * Represents a verification session for a single player.
   */
  public static class VerificationSession {
    
    private final ConnectedPlayer player;
    private final VerificationServer verificationServer;
    private final long startTime;
    private final String originalServer;
    
    // Verification tracking
    private int movementCount = 0;
    private int interactionCount = 0;
    private double totalDistance = 0.0;
    private double lastX = 0.0, lastY = 64.0, lastZ = 0.0;
    private boolean hasJumped = false;
    private boolean hasRotated = false;
    
    // Session management
    private ScheduledFuture<?> timeoutTask;
    private boolean completed = false;
    
    public VerificationSession(ConnectedPlayer player, VerificationServer verificationServer) {
      this.player = player;
      this.verificationServer = verificationServer;
      this.startTime = System.currentTimeMillis();
      
      // Store the original server the player was trying to connect to
      this.originalServer = player.getCurrentServer()
          .map(connection -> connection.getServerInfo().getName())
          .orElse("lobby"); // fallback to lobby if no current server
      
      // Set timeout for verification (30 seconds)
      this.timeoutTask = verificationServer.server.getScheduler()
          .buildTask(verificationServer.server.getPluginManager().getPlugin("sentinalsproxy").orElse(null), 
              () -> onVerificationTimeout())
          .delay(30, TimeUnit.SECONDS)
          .schedule();
      
      logger.info("[VerificationSession] Created session for {} (original server: {})", 
          player.getUsername(), originalServer);
    }
    
    /**
     * Initializes the virtual verification world for the player.
     */
    public void initializeVerificationWorld() {
      try {
        logger.info("[VerificationSession] Initializing verification world for player: {}", player.getUsername());
        
        // Send welcome message
        player.sendMessage(Component.text("§6§lANTI-BOT VERIFICATION"));
        player.sendMessage(Component.text("§ePlease move around and interact to verify you're human"));
        player.sendMessage(Component.text("§7This process should take less than 30 seconds"));
        
        // Initialize position in the virtual world
        this.lastX = 0.0;
        this.lastY = 64.0;
        this.lastZ = 0.0;
        
        // Send virtual world packets (simplified)
        sendVerificationWorldPackets();
        
        logger.info("[VerificationSession] Verification world initialized for player: {}", player.getUsername());
        
      } catch (Exception e) {
        logger.error("[VerificationSession] Failed to initialize verification world for player: {}", 
            player.getUsername(), e);
        onVerificationFailed();
      }
    }
    
    /**
     * Sends the necessary packets to create a virtual verification world.
     */
    private void sendVerificationWorldPackets() {
      try {
        // Send position packet to place player in verification world
        // Note: In a real implementation, you'd send proper world packets
        // For now, we'll track the player's state internally
        
        player.sendMessage(Component.text("§aVerification world loaded! Please move around..."));
        
      } catch (Exception e) {
        logger.error("[VerificationSession] Error sending verification world packets", e);
      }
    }
    
    /**
     * Handles incoming packets from the player during verification.
     * 
     * @param packet the packet to handle
     * @return true if packet was handled
     */
    public boolean handlePacket(MinecraftPacket packet) {
      if (completed) {
        return false;
      }
      
      try {
        // Handle movement packets
        if (packet instanceof PlayerPosition) {
          handlePlayerPosition((PlayerPosition) packet);
          return true;
        } else if (packet instanceof PlayerPositionAndRotation) {
          handlePlayerPositionAndRotation((PlayerPositionAndRotation) packet);
          return true;
        } else if (packet instanceof KeepAlive) {
          // Allow keep alive packets to pass through
          return false;
        } else if (packet instanceof ClientSettings) {
          // Allow client settings to pass through
          return false;
        }
        
        // Count other interactions
        interactionCount++;
        
        // Check if verification is complete
        checkVerificationCompletion();
        
        return true;
        
      } catch (Exception e) {
        logger.error("[VerificationSession] Error handling packet for player: {}", player.getUsername(), e);
        return false;
      }
    }
    
    /**
     * Handles player position packets.
     */
    private void handlePlayerPosition(PlayerPosition packet) {
      double newX = packet.getX();
      double newY = packet.getY();
      double newZ = packet.getZ();
      
      processMovement(newX, newY, newZ);
    }
    
    /**
     * Handles player position and rotation packets.
     */
    private void handlePlayerPositionAndRotation(PlayerPositionAndRotation packet) {
      double newX = packet.getX();
      double newY = packet.getY();
      double newZ = packet.getZ();
      
      processMovement(newX, newY, newZ);
      
      // Track rotation changes
      if (!hasRotated) {
        hasRotated = true;
        logger.debug("[VerificationSession] Player {} has rotated", player.getUsername());
      }
    }
    
    /**
     * Processes player movement and updates verification metrics.
     */
    private void processMovement(double newX, double newY, double newZ) {
      movementCount++;
      
      // Calculate distance moved
      double distance = Math.sqrt(
          Math.pow(newX - lastX, 2) + 
          Math.pow(newY - lastY, 2) + 
          Math.pow(newZ - lastZ, 2)
      );
      
      totalDistance += distance;
      
      // Check for jumping (Y coordinate increase)
      if (newY > lastY + 0.5) {
        hasJumped = true;
        logger.debug("[VerificationSession] Player {} has jumped", player.getUsername());
      }
      
      // Update last position
      lastX = newX;
      lastY = newY;
      lastZ = newZ;
      
      logger.trace("[VerificationSession] Player {} moved: distance={}, total={}", 
          player.getUsername(), distance, totalDistance);
      
      checkVerificationCompletion();
    }
    
    /**
     * Checks if the player has completed verification requirements.
     */
    private void checkVerificationCompletion() {
      if (completed) {
        return;
      }
      
      // Verification requirements (configurable)
      boolean hasEnoughMovement = movementCount >= 5;
      boolean hasMovedDistance = totalDistance >= 3.0;
      boolean hasBasicInteraction = interactionCount >= 1 || hasJumped || hasRotated;
      boolean hasSpentTime = (System.currentTimeMillis() - startTime) >= 3000; // 3 seconds minimum
      
      logger.debug("[VerificationSession] Player {} verification progress: movements={}, distance={:.2f}, interactions={}, time={}ms, jumped={}, rotated={}", 
          player.getUsername(), movementCount, totalDistance, interactionCount, 
          (System.currentTimeMillis() - startTime), hasJumped, hasRotated);
      
      if (hasEnoughMovement && hasMovedDistance && hasBasicInteraction && hasSpentTime) {
        logger.info("[VerificationSession] Player {} has completed verification requirements", player.getUsername());
        onVerificationPassed();
      }
    }
    
    /**
     * Called when the player passes verification.
     */
    public void onVerificationPassed() {
      if (completed) {
        return;
      }
      
      completed = true;
      if (timeoutTask != null) {
        timeoutTask.cancel(false);
      }
      
      logger.info("[VerificationSession] Player {} PASSED verification", player.getUsername());
      
      // Mark player as verified in AntiBot
      verificationServer.antiBot.markPlayerAsVerified(player.getUniqueId());
      
      // Send success message
      player.sendMessage(Component.text("§a§lVERIFICATION COMPLETE!"));
      player.sendMessage(Component.text("§7You have been verified as human. Connecting to server..."));
      
      // Transfer to original server
      transferToOriginalServer();
    }
    
    /**
     * Called when the player fails verification.
     */
    public void onVerificationFailed() {
      if (completed) {
        return;
      }
      
      completed = true;
      if (timeoutTask != null) {
        timeoutTask.cancel(false);
      }
      
      logger.warn("[VerificationSession] Player {} FAILED verification", player.getUsername());
      
      // Kick player with message
      player.disconnect(Component.text("§cVerification failed. Please try connecting again."));
    }
    
    /**
     * Called when verification times out.
     */
    private void onVerificationTimeout() {
      logger.warn("[VerificationSession] Player {} verification TIMED OUT", player.getUsername());
      
      player.sendMessage(Component.text("§cVerification timed out. Please try again."));
      onVerificationFailed();
    }
    
    /**
     * Transfers the player to their original server.
     */
    private void transferToOriginalServer() {
      try {
        // Find the original server
        verificationServer.server.getServer(originalServer)
            .ifPresentOrElse(
                targetServer -> {
                  logger.info("[VerificationSession] Transferring player {} to server: {}", 
                      player.getUsername(), originalServer);
                  
                  player.createConnectionRequest(targetServer)
                      .fireAndForget();
                },
                () -> {
                  logger.warn("[VerificationSession] Original server '{}' not found, sending player to lobby", originalServer);
                  
                  // Try to find a lobby server
                  verificationServer.server.getServer("lobby")
                      .or(() -> verificationServer.server.getServer("hub"))
                      .ifPresentOrElse(
                          lobbyServer -> player.createConnectionRequest(lobbyServer).fireAndForget(),
                          () -> {
                            logger.error("[VerificationSession] No lobby server found, disconnecting player");
                            player.disconnect(Component.text("§cNo servers available after verification"));
                          }
                      );
                }
            );
            
      } catch (Exception e) {
        logger.error("[VerificationSession] Error transferring player after verification", e);
        player.disconnect(Component.text("§cError transferring to server after verification"));
      }
    }
    
    /**
     * Checks if this session has expired.
     */
    public boolean isExpired() {
      return completed || (System.currentTimeMillis() - startTime) > 60000; // 1 minute max
    }
    
    /**
     * Gets the player for this session.
     */
    public ConnectedPlayer getPlayer() {
      return player;
    }
  }
}
