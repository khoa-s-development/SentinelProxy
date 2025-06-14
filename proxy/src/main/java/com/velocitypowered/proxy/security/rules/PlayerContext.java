/*
 * Copyright (C) 2018-2023 Velocity Contributors
 * Current Date and Time (UTC): 2025-06-13 18:23:41
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security.rules;

import com.velocitypowered.api.proxy.Player;
import java.net.InetAddress;

public class PlayerContext extends SecurityContext {
    private final Player player;
    private boolean disconnected;

    public PlayerContext(Player player) {
        this.player = player;
        this.disconnected = false;
    }

    @Override
    public InetAddress getAddress() {
        return player.getRemoteAddress().getAddress();
    }

    public Player getPlayer() {
        return player;
    }

    public void disconnect(String reason) {
        this.disconnected = true;
        this.reason = reason;
    }

    public boolean isDisconnected() {
        return disconnected;
    }
}