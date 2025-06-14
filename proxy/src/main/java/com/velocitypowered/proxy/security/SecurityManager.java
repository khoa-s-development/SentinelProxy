/*
 * Copyright (C) 2018-2023 Velocity Contributors
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

package com.velocitypowered.proxy.security;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.protocol.packet.LoginPacket;
import com.velocitypowered.proxy.security.crypto.EncryptionManager;
import com.velocitypowered.proxy.security.store.SecurityStore;
import com.velocitypowered.proxy.security.rules.SecurityRuleEngine;

import java.net.InetAddress;
import java.util.concurrent.CompletableFuture;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SecurityManager {
    private static final Logger logger = LogManager.getLogger(SecurityManager.class);

    private final VelocityServer server;
    private final SecurityStore securityStore;
    private final EncryptionManager encryptionManager;
    private final SecurityRuleEngine ruleEngine;
    
    // Configurable settings
    private boolean enforceSecureProfile = true;
    private int minKeySize = 2048;
    private int sessionTimeout = 3600;

    public SecurityManager(VelocityServer server) {
        this.server = server;
        this.securityStore = new SecurityStore();
        this.encryptionManager = new EncryptionManager(minKeySize);
        this.ruleEngine = new SecurityRuleEngine();
        
        // Register event listeners
        server.getEventManager().register(this, this);
    }

    public void start() {
        logger.info("Starting SecurityManager...");
        loadConfiguration();
        securityStore.initialize();
        encryptionManager.initialize();
        ruleEngine.loadRules();
    }

    public void shutdown() {
        logger.info("Shutting down SecurityManager...");
        securityStore.close();
    }

    public void reload() {
        logger.info("Reloading SecurityManager...");
        loadConfiguration();
        ruleEngine.reloadRules();
    }

    private void loadConfiguration() {
        // Load from velocity.toml
        if (server.getConfiguration() != null) {
            this.enforceSecureProfile = server.getConfiguration().isForceKeyAuthentication();
            // Load other security settings
        }
    }

    @Subscribe
    public void onPreLogin(PreLoginEvent event) {
        // Validate connection before login
        CompletableFuture.runAsync(() -> {
            try {
                if (!validateConnection(event)) {
                    event.setResult(PreLoginEvent.PreLoginComponentResult.denied());
                }
            } catch (Exception e) {
                logger.error("Error validating connection", e);
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied());
            }
        });
    }

    @Subscribe 
    public void onLogin(LoginEvent event) {
        // Validate player on login
        try {
            if (!validatePlayer(event.getPlayer())) {
                event.setResult(LoginEvent.LoginResult.denied());
            }
        } catch (Exception e) {
            logger.error("Error validating player login", e);
            event.setResult(LoginEvent.LoginResult.denied());
        }
    }

    private boolean validateConnection(PreLoginEvent event) {
        // Check security rules
        return ruleEngine.validateConnection(event.getConnection());
    }

    private boolean validatePlayer(Player player) {
        // Validate player security
        return ruleEngine.validatePlayer(player);
    }

    public SecurityStore getSecurityStore() {
        return securityStore;
    }

    public EncryptionManager getEncryptionManager() {
        return encryptionManager;
    }

    public SecurityRuleEngine getRuleEngine() {
        return ruleEngine;
    }

    public boolean isEnforceSecureProfile() {
        return enforceSecureProfile;
    }

    public void setEnforceSecureProfile(boolean enforceSecureProfile) {
        this.enforceSecureProfile = enforceSecureProfile;
    }
}