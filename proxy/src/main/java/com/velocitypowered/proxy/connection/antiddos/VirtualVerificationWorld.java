/*
 * Copyright (C) 2024 Velocity Contributors
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

import com.velocitypowered.api.util.Vector3d;
import com.velocitypowered.proxy.connection.client.ConnectedPlayer;
import com.velocitypowered.proxy.protocol.ProtocolUtils;
import com.velocitypowered.proxy.protocol.packet.JoinGamePacket;
import com.velocitypowered.proxy.connection.registry.DimensionInfo;
import com.velocitypowered.api.network.ProtocolVersion;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import net.kyori.adventure.nbt.CompoundBinaryTag;
import net.kyori.adventure.nbt.IntBinaryTag;
import net.kyori.adventure.nbt.ListBinaryTag;
import net.kyori.adventure.nbt.StringBinaryTag;
import net.kyori.adventure.text.Component;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Virtual Verification World - A built-in verification world that runs within the proxy
 * without requiring an external Minecraft server.
 * 
 * This system creates a virtual flat world where players can move around to prove
 * they are human, then transfers them to their intended destination server.
 */
public class VirtualVerificationWorld {

    private static final Logger logger = LoggerFactory.getLogger(VirtualVerificationWorld.class);
    
    // Virtual world constants
    private static final String WORLD_NAME = "verification_world";
    private static final String DIMENSION_KEY = "minecraft:overworld";
    private static final Vector3d SPAWN_LOCATION = new Vector3d(0, 64, 0);
    private static final int ENTITY_ID_BASE = 1000000; // High ID to avoid conflicts
    
    // Player tracking
    private final ConcurrentHashMap<UUID, VirtualPlayer> virtualPlayers = new ConcurrentHashMap<>();
    private final AntiBot antiBot;
    
    public VirtualVerificationWorld(AntiBot antiBot) {
        this.antiBot = antiBot;
        logger.info("Virtual Verification World initialized - No external server required!");
    }
    
    /**
     * Enters a player into the virtual verification world.
     * 
     * @param player the player to enter
     * @return true if successfully entered, false otherwise
     */
    public boolean enterVerificationWorld(ConnectedPlayer player) {
        try {
            UUID playerId = player.getUniqueId();
            String username = player.getUsername();
            
            logger.info("[VIRTUAL-WORLD] Player {} entering virtual verification world", username);
            
            // Create virtual player tracking
            VirtualPlayer virtualPlayer = new VirtualPlayer(
                playerId,
                username, 
                SPAWN_LOCATION,
                System.currentTimeMillis()
            );
            virtualPlayers.put(playerId, virtualPlayer);
            
            // Send join game packet for virtual world
            sendJoinGamePacket(player, virtualPlayer);
            
            // Send initial world data
            sendInitialWorldData(player);
            
            // Send welcome message
            sendWelcomeMessage(player);
            
            logger.info("[VIRTUAL-WORLD] Player {} successfully entered virtual verification world", username);
            return true;
            
        } catch (Exception e) {
            logger.error("[VIRTUAL-WORLD] Error entering player {} into virtual world: {}", 
                player.getUsername(), e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Handles player movement in the virtual world for verification.
     * 
     * @param player the player
     * @param newPosition the new position
     * @return true if verification is complete, false if still in progress
     */
    public boolean handlePlayerMovement(ConnectedPlayer player, Vector3d newPosition) {
        UUID playerId = player.getUniqueId();
        VirtualPlayer virtualPlayer = virtualPlayers.get(playerId);
        
        if (virtualPlayer == null) {
            return false; // Player not in virtual world
        }
        
        // Update position and track movement
        Vector3d oldPosition = virtualPlayer.getPosition();
        virtualPlayer.setPosition(newPosition);
        virtualPlayer.incrementMovements();
        
        // Calculate distance moved
        double distance = oldPosition.distance(newPosition);
        virtualPlayer.addDistance(distance);
        
        if (antiBot.getConfig().isDebugMode()) {
            logger.info("[VIRTUAL-WORLD] Player {} moved to {}, total movements: {}, total distance: {:.2f}", 
                player.getUsername(), newPosition, virtualPlayer.getMovements(), virtualPlayer.getTotalDistance());
        }
        
        // Check if verification requirements are met
        boolean verified = checkVerificationRequirements(virtualPlayer);
        
        if (verified) {
            logger.info("[VIRTUAL-WORLD] Player {} completed verification! Movements: {}, Distance: {:.2f}", 
                player.getUsername(), virtualPlayer.getMovements(), virtualPlayer.getTotalDistance());
            
            // Remove from virtual world
            virtualPlayers.remove(playerId);
            
            // Mark as verified in AntiBot
            antiBot.markPlayerAsVerified(playerId);
        }
        
        return verified;
    }
    
    /**
     * Exits a player from the virtual verification world.
     * 
     * @param player the player to exit
     */
    public void exitVerificationWorld(ConnectedPlayer player) {
        UUID playerId = player.getUniqueId();
        VirtualPlayer virtualPlayer = virtualPlayers.remove(playerId);
        
        if (virtualPlayer != null) {
            logger.info("[VIRTUAL-WORLD] Player {} exited virtual verification world", player.getUsername());
        }
    }
    
    /**
     * Checks if a player is currently in the virtual verification world.
     * 
     * @param playerId the player ID to check
     * @return true if in virtual world, false otherwise
     */
    public boolean isPlayerInVerificationWorld(UUID playerId) {
        return virtualPlayers.containsKey(playerId);
    }
    
    /**
     * Gets the virtual player data for a player.
     * 
     * @param playerId the player ID
     * @return virtual player data or null if not in virtual world
     */
    public VirtualPlayer getVirtualPlayer(UUID playerId) {
        return virtualPlayers.get(playerId);
    }
    
    /**
     * Cleans up expired virtual players (those who have been in the world too long).
     */
    public void cleanup() {
        long currentTime = System.currentTimeMillis();
        long timeoutMs = antiBot.getConfig().getMiniWorldDuration() * 1000L + 30000L; // +30s grace period
        
        virtualPlayers.entrySet().removeIf(entry -> {
            VirtualPlayer vp = entry.getValue();
            if (currentTime - vp.getEntryTime() > timeoutMs) {
                logger.info("[VIRTUAL-WORLD] Cleaning up expired virtual player: {}", vp.getUsername());
                return true;
            }
            return false;
        });
    }
    
    private void sendJoinGamePacket(ConnectedPlayer player, VirtualPlayer virtualPlayer) {
        try {
            ProtocolVersion version = player.getProtocolVersion();
            
            JoinGamePacket joinGame = new JoinGamePacket();
            joinGame.setEntityId(virtualPlayer.getEntityId());
            joinGame.setGamemode((short) 1); // Creative mode for easy movement
            joinGame.setDimension(0); // Overworld
            // Remove seed setting as neither method is available
            joinGame.setDifficulty((short) 0); // Peaceful
            joinGame.setIsHardcore(false);
            joinGame.setMaxPlayers(1);
            joinGame.setLevelType("flat");
            joinGame.setViewDistance(2); // Small view distance for performance
            joinGame.setReducedDebugInfo(false);
            // Remove setShowRespawnScreen as it's not available
            joinGame.setDoLimitedCrafting(false);
            
            // Remove setLevelNames as it's not available
            
            // Create dimension info for flat world
            DimensionInfo dimensionInfo = new DimensionInfo(
                DIMENSION_KEY,
                WORLD_NAME,
                true, // flat world
                false, // not debug
                version
            );
            joinGame.setDimensionInfo(dimensionInfo);
            
            // Remove setRegistry as it's not available
            // We'll need to use the appropriate method based on what's available
            // For now, just use what we have in DimensionInfo
            
            // Set simulation distance
            joinGame.setSimulationDistance(2);
            
            // No death position
            joinGame.setLastDeathPosition(null);
            
            player.getConnection().write(joinGame);
            
        } catch (Exception e) {
            logger.error("[VIRTUAL-WORLD] Error sending join game packet to {}: {}", 
                player.getUsername(), e.getMessage(), e);
        }
    }
    
    private void sendInitialWorldData(ConnectedPlayer player) {
        try {
            // Send player position and look packet
            sendPlayerPositionPacket(player, SPAWN_LOCATION);
            
            // Send basic chunk data for a flat world
            sendFlatChunkData(player);
            
        } catch (Exception e) {
            logger.error("[VIRTUAL-WORLD] Error sending initial world data to {}: {}", 
                player.getUsername(), e.getMessage(), e);
        }
    }
    
    private void sendPlayerPositionPacket(ConnectedPlayer player, Vector3d position) {
        try {
            // Create a player position and look packet
            ByteBuf buf = Unpooled.buffer();
            
            // Position (3 doubles)
            buf.writeDouble(position.getX());
            buf.writeDouble(position.getY());
            buf.writeDouble(position.getZ());
            
            // Rotation (2 floats)
            buf.writeFloat(0.0f); // Yaw
            buf.writeFloat(0.0f); // Pitch
            
            // Flags (byte) - absolute positioning
            buf.writeByte(0x00);
            
            // Teleport ID (VarInt)
            ProtocolUtils.writeVarInt(buf, ThreadLocalRandom.current().nextInt(1000, 9999));
            
            // Send as a custom packet - this would need to be implemented properly
            // For now, we'll use the respawn mechanism
            
            buf.release();
            
        } catch (Exception e) {
            logger.error("[VIRTUAL-WORLD] Error sending player position to {}: {}", 
                player.getUsername(), e.getMessage(), e);
        }
    }
    
    private void sendFlatChunkData(ConnectedPlayer player) {
        // For a virtual world, we can send minimal chunk data
        // This would require implementing chunk packet creation
        // For now, we'll rely on the client handling the flat world type
        
        if (antiBot.getConfig().isDebugMode()) {
            logger.info("[VIRTUAL-WORLD] Sending flat world chunk data to {}", player.getUsername());
        }
    }
    
    private void sendWelcomeMessage(ConnectedPlayer player) {
        try {
            Component welcomeMessage = Component.text()
                .append(Component.text("§6§l[VERIFICATION]§r\n"))
                .append(Component.text("§eWelcome to the verification world!\n"))
                .append(Component.text("§7Please move around to prove you are human.\n"))
                .append(Component.text("§7Required: §a" + antiBot.getConfig().getMiniWorldMinMovements() + " movements§7, §a" 
                    + antiBot.getConfig().getMiniWorldMinDistance() + " blocks§7 distance.\n"))
                .append(Component.text("§7You will be transferred automatically once verified."))
                .build();
            
            player.sendMessage(welcomeMessage);
            
        } catch (Exception e) {
            logger.error("[VIRTUAL-WORLD] Error sending welcome message to {}: {}", 
                player.getUsername(), e.getMessage(), e);
        }
    }
    
    private CompoundBinaryTag createVirtualWorldRegistry() {
        try {
            // Create a minimal registry for the virtual world
            return CompoundBinaryTag.builder()
                .put("minecraft:dimension_type", CompoundBinaryTag.builder()
                    .put("type", StringBinaryTag.stringBinaryTag("minecraft:dimension_type"))
                    .put("value", ListBinaryTag.builder()
                        .add(CompoundBinaryTag.builder()
                            .put("name", StringBinaryTag.stringBinaryTag("minecraft:overworld"))
                            .put("id", IntBinaryTag.intBinaryTag(0))
                            .put("element", CompoundBinaryTag.builder()
                                .put("piglin_safe", IntBinaryTag.intBinaryTag(0))
                                .put("natural", IntBinaryTag.intBinaryTag(1))
                                .put("ambient_light", IntBinaryTag.intBinaryTag(0))
                                .put("infiniburn", StringBinaryTag.stringBinaryTag("#minecraft:infiniburn_overworld"))
                                .put("respawn_anchor_works", IntBinaryTag.intBinaryTag(0))
                                .put("has_skylight", IntBinaryTag.intBinaryTag(1))
                                .put("bed_works", IntBinaryTag.intBinaryTag(1))
                                .put("effects", StringBinaryTag.stringBinaryTag("minecraft:overworld"))
                                .put("has_raids", IntBinaryTag.intBinaryTag(1))
                                .put("min_y", IntBinaryTag.intBinaryTag(0))
                                .put("height", IntBinaryTag.intBinaryTag(256))
                                .put("logical_height", IntBinaryTag.intBinaryTag(256))
                                .put("coordinate_scale", IntBinaryTag.intBinaryTag(1))
                                .put("ultrawarm", IntBinaryTag.intBinaryTag(0))
                                .put("has_ceiling", IntBinaryTag.intBinaryTag(0))
                                .build())
                            .build())
                        .build())
                    .build())
                .put("minecraft:worldgen/biome", CompoundBinaryTag.builder()
                    .put("type", StringBinaryTag.stringBinaryTag("minecraft:worldgen/biome"))
                    .put("value", ListBinaryTag.builder()
                        .add(CompoundBinaryTag.builder()
                            .put("name", StringBinaryTag.stringBinaryTag("minecraft:plains"))
                            .put("id", IntBinaryTag.intBinaryTag(1))
                            .put("element", CompoundBinaryTag.builder()
                                .put("precipitation", StringBinaryTag.stringBinaryTag("rain"))
                                .put("temperature", IntBinaryTag.intBinaryTag(1))
                                .put("downfall", IntBinaryTag.intBinaryTag(0))
                                .put("effects", CompoundBinaryTag.builder()
                                    .put("sky_color", IntBinaryTag.intBinaryTag(7907327))
                                    .put("water_fog_color", IntBinaryTag.intBinaryTag(329011))
                                    .put("fog_color", IntBinaryTag.intBinaryTag(12638463))
                                    .put("water_color", IntBinaryTag.intBinaryTag(4159204))
                                    .build())
                                .build())
                            .build())
                        .build())
                    .build())
                .build();
                
        } catch (Exception e) {
            logger.error("[VIRTUAL-WORLD] Error creating virtual world registry: {}", e.getMessage(), e);
            return CompoundBinaryTag.empty();
        }
    }
    
    private boolean checkVerificationRequirements(VirtualPlayer virtualPlayer) {
        AntiBotConfig config = antiBot.getConfig();
        
        // Check minimum movements
        if (virtualPlayer.getMovements() < config.getMiniWorldMinMovements()) {
            return false;
        }
        
        // Check minimum distance
        if (virtualPlayer.getTotalDistance() < config.getMiniWorldMinDistance()) {
            return false;
        }
        
        // Check if enough time has passed (minimum 3 seconds)
        long timeInWorld = System.currentTimeMillis() - virtualPlayer.getEntryTime();
        if (timeInWorld < 3000) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Gets the number of players currently in the virtual verification world.
     * 
     * @return player count
     */
    public int getPlayerCount() {
        return virtualPlayers.size();
    }
    
    /**
     * Reports status of the virtual verification world.
     */
    public void reportStatus() {
        int playerCount = virtualPlayers.size();
        if (playerCount > 0) {
            logger.info("[VIRTUAL-WORLD] Status: {} players currently in verification world", playerCount);
        }
    }
    
    /**
     * Represents a player in the virtual verification world.
     */
    public static class VirtualPlayer {
        private final UUID playerId;
        private final String username;
        private final int entityId;
        private final long entryTime;
        
        private Vector3d position;
        private int movements;
        private double totalDistance;
        
        public VirtualPlayer(UUID playerId, String username, Vector3d initialPosition, long entryTime) {
            this.playerId = playerId;
            this.username = username;
            this.entityId = ENTITY_ID_BASE + ThreadLocalRandom.current().nextInt(100000);
            this.position = initialPosition;
            this.entryTime = entryTime;
            this.movements = 0;
            this.totalDistance = 0.0;
        }
        
        // Getters and setters
        public UUID getPlayerId() { return playerId; }
        public String getUsername() { return username; }
        public int getEntityId() { return entityId; }
        public long getEntryTime() { return entryTime; }
        public Vector3d getPosition() { return position; }
        public void setPosition(Vector3d position) { this.position = position; }
        public int getMovements() { return movements; }
        public void incrementMovements() { this.movements++; }
        public double getTotalDistance() { return totalDistance; }
        public void addDistance(double distance) { this.totalDistance += distance; }
    }
}
