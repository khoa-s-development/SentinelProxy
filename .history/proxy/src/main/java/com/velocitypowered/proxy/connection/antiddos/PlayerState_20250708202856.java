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

import com.velocitypowered.api.util.Vector3d;

import java.net.InetAddress;
import java.util.LinkedList;
import java.util.Queue;
import java.util.UUID;

/**
 * Represents the state of a player for anti-bot protection.
 * Tracks position, rotation, and other metrics to detect bot behavior.
 */
public class PlayerState {
    private final UUID playerId;
    private final InetAddress address;
    private final long connectionTime;
    private long lastUpdateTime;
    private long lastPositiveYVelocityTime;
    
    private Vector3d currentPosition;
    private Vector3d lastPosition;
    private float currentYaw;
    private float lastYaw;
    private float currentPitch;
    private float lastPitch;
    
    private boolean onGround;
    private int moveCount;
    private int interactionCount;
    private int yawViolations;
    private int gravityViolations;
    
    private Queue<Float> yawHistory = new LinkedList<>();
    private static final int YAW_HISTORY_SIZE = 10;
    
    /**
     * Creates a new player state.
     *
     * @param playerId the UUID of the player
     * @param address the IP address of the player
     */
    public PlayerState(UUID playerId, InetAddress address) {
        this.playerId = playerId;
        this.address = address;
        this.connectionTime = System.currentTimeMillis();
        this.lastUpdateTime = this.connectionTime;
        this.lastPositiveYVelocityTime = 0;
        this.currentPosition = new Vector3d(0, 0, 0);
        this.lastPosition = new Vector3d(0, 0, 0);
        this.currentYaw = 0;
        this.lastYaw = 0;
        this.currentPitch = 0;
        this.lastPitch = 0;
        this.onGround = true;
        this.moveCount = 0;
        this.interactionCount = 0;
    }
    
    /**
     * Updates the position and rotation of the player.
     *
     * @param x the new x coordinate
     * @param y the new y coordinate
     * @param z the new z coordinate
     * @param yaw the new yaw
     * @param pitch the new pitch
     */
    public void updatePositionAndRotation(double x, double y, double z, float yaw, float pitch) {
        lastPosition = currentPosition;
        lastYaw = currentYaw;
        lastPitch = currentPitch;
        
        currentPosition = new Vector3d(x, y, z);
        currentYaw = yaw;
        currentPitch = pitch;
        
        if (y > lastPosition.getY()) {
            lastPositiveYVelocityTime = System.currentTimeMillis();
        }
        
        // Add to yaw history
        yawHistory.add(yaw);
        if (yawHistory.size() > YAW_HISTORY_SIZE) {
            yawHistory.poll();
        }
        
        moveCount++;
        lastUpdateTime = System.currentTimeMillis();
    }
    
    /**
     * Gets the current position of the player.
     *
     * @return the current position
     */
    public Vector3d getCurrentPosition() {
        return currentPosition;
    }
    
    /**
     * Gets the last position of the player.
     *
     * @return the last position
     */
    public Vector3d getLastPosition() {
        return lastPosition;
    }
    
    /**
     * Gets the current yaw of the player.
     *
     * @return the current yaw
     */
    public float getCurrentYaw() {
        return currentYaw;
    }
    
    /**
     * Gets the last yaw of the player.
     *
     * @return the last yaw
     */
    public float getLastYaw() {
        return lastYaw;
    }
    
    /**
     * Gets the current pitch of the player.
     *
     * @return the current pitch
     */
    public float getCurrentPitch() {
        return currentPitch;
    }
    
    /**
     * Gets the last pitch of the player.
     *
     * @return the last pitch
     */
    public float getLastPitch() {
        return lastPitch;
    }
    
    /**
     * Gets whether the player is on the ground.
     *
     * @return whether the player is on the ground
     */
    public boolean isOnGround() {
        return onGround;
    }
    
    /**
     * Sets whether the player is on the ground.
     *
     * @param onGround whether the player is on the ground
     */
    public void setOnGround(boolean onGround) {
        this.onGround = onGround;
    }
    
    /**
     * Gets whether this is the player's first move.
     *
     * @return whether this is the first move
     */
    public boolean isFirstMove() {
        return moveCount <= 1;
    }
    
    /**
     * Gets the number of moves the player has made.
     *
     * @return the move count
     */
    public int getMoveCount() {
        return moveCount;
    }
    
    /**
     * Gets the number of interactions the player has made.
     *
     * @return the interaction count
     */
    public int getInteractionCount() {
        return interactionCount;
    }
    
    /**
     * Increments the interaction count.
     */
    public void incrementInteractionCount() {
        interactionCount++;
        lastUpdateTime = System.currentTimeMillis();
    }
    
    /**
     * Gets the time in seconds since the player had positive Y velocity.
     *
     * @return the time in seconds
     */
    public double getSecondsSincePositiveYVelocity() {
        if (lastPositiveYVelocityTime == 0) {
            return 0;
        }
        return (System.currentTimeMillis() - lastPositiveYVelocityTime) / 1000.0;
    }
    
    /**
     * Gets the time in seconds since the player connected.
     *
     * @return the time in seconds
     */
    public double getTimeSinceConnection() {
        return (System.currentTimeMillis() - connectionTime) / 1000.0;
    }
    
    /**
     * Gets the last update time of the player.
     *
     * @return the last update time
     */
    public long getLastUpdateTime() {
        return lastUpdateTime;
    }
    
    /**
     * Determines if we have enough data to perform checks.
     *
     * @return whether we have enough data
     */
    public boolean hasEnoughData() {
        return moveCount >= 3;
    }
    
    /**
     * Gets the number of yaw violations.
     *
     * @return the yaw violations
     */
    public int getYawViolations() {
        return yawViolations;
    }
    
    /**
     * Increments the yaw violations.
     */
    public void incrementYawViolations() {
        yawViolations++;
    }
    
    /**
     * Resets the yaw violations.
     */
    public void resetYawViolations() {
        yawViolations = 0;
    }
    
    /**
     * Gets the number of gravity violations.
     *
     * @return the gravity violations
     */
    public int getGravityViolations() {
        return gravityViolations;
    }
    
    /**
     * Increments the gravity violations.
     */
    public void incrementGravityViolation() {
        gravityViolations++;
    }
    
    /**
     * Resets the gravity violations.
     */
    public void resetGravityViolation() {
        gravityViolations = 0;
    }
    
    /**
     * Checks if the player has a repeated rotation pattern.
     *
     * @return whether the player has a repeated rotation pattern
     */
    public boolean hasRepeatedRotationPattern() {
        if (yawHistory.size() < YAW_HISTORY_SIZE) {
            return false;
        }
        
        // Check for identical patterns in yaw changes
        float[] yawArray = new float[yawHistory.size()];
        for (int i = 0; i < yawHistory.size(); i++) {
            yawArray[i] = yawHistory.get(i);
        }
        
        float[] diffs = new float[yawArray.length - 1];
        
        for (int i = 0; i < diffs.length; i++) {
            diffs[i] = yawArray[i + 1] - yawArray[i];
        }
        
        // Check for repeating pattern (same yaw difference multiple times)
        int repeats = 0;
        for (int i = 0; i < diffs.length - 1; i++) {
            if (Math.abs(diffs[i] - diffs[i + 1]) < 0.01) {
                repeats++;
                if (repeats >= 3) {
                    return true;
                }
            } else {
                repeats = 0;
            }
        }
        
        return false;
    }
}
