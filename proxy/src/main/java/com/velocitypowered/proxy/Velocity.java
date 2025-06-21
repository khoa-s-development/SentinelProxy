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
 *
 * Current Date and Time (UTC): 2025-06-21 02:05:19
 * Current User's Login: akk1to
 */

package com.velocitypowered.proxy;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.proxy.config.VelocityConfiguration;
import com.velocitypowered.proxy.protection.*;
import com.velocitypowered.proxy.monitoring.MonitoringManager;
import com.velocitypowered.proxy.command.builtin.VelocityCommand;
import com.velocitypowered.proxy.command.builtin.ServerCommand;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;

@Plugin(
    id = "SentinelsProxy",
    name = "SentinelsProxy",
    version = "2.0.0",
    url = "https://zyndata.vn",
    description = "A Fully AntiDDoS , Anti Exploit, Modern and hotswaping Proxy.",
    authors = {"Velocity Team"}
)
public class Velocity {

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;
    private final ScheduledExecutorService scheduler;

    // Core components
    private VelocityConfiguration configuration;
    private ComponentRegistry componentRegistry;
    private CommandRegistry commandRegistry;
    private EventRegistry eventRegistry;

    // Protection components 
    private SecurityManager securityManager;
    private MonitoringManager monitoringManager;

    // Missing fields
    private ApiServer apiServer;
    private UpdateChecker updateChecker;

    @Inject
    public Velocity(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
        this.scheduler = Executors.newScheduledThreadPool(4);
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        try {
            // Initialize core components first
            initializeComponents();

            // Load configuration
            if (configuration != null) {
                configuration.load();
            }

            // Register commands
            registerCommands();

            // Register event handlers
            registerEventHandlers();

            // Start services
            startServices();

            // Schedule tasks
            scheduleTasks();

            logger.info("Velocity Recoded has been initialized");

        } catch (Exception e) {
            logger.error("Failed to initialize Velocity", e);
            throw new RuntimeException("Failed to initialize Velocity", e);
        }
    }

    @Subscribe 
    public void onProxyShutdown(ProxyShutdownEvent event) {
        try {
            // Stop services
            stopServices();

            // Save data
            saveData();

            // Cleanup resources
            cleanup();

            logger.info("Velocity has been shutdown");

        } catch (Exception e) {
            logger.error("Error during shutdown", e);
        }
    }

    private void initializeComponents() {
        try {
            // Initialize configuration first
            this.configuration = VelocityConfiguration.read(dataDirectory.resolve("velocity.toml"));
            
            // Initialize other components
            this.componentRegistry = new ComponentRegistry(this);
            this.commandRegistry = new CommandRegistry(this);
            this.eventRegistry = new EventRegistry(this);
            this.securityManager = new SecurityManager();
            this.monitoringManager = new MonitoringManager(server);
            
            // Initialize missing components
            this.apiServer = new ApiServer();
            this.updateChecker = new UpdateChecker();

            // Initialize components
            if (componentRegistry != null) {
                componentRegistry.initialize();
            }
            if (securityManager != null) {
                securityManager.initialize();
            }
            if (monitoringManager != null) {
                monitoringManager.initialize();
            }
        } catch (Exception e) {
            logger.error("Failed to initialize components", e);
        }
    }

    private void registerCommands() {
        try {
            if (server instanceof VelocityServer velocityServer) {
                // Register built-in commands using the existing builtin classes
                server.getCommandManager().register(VelocityCommand.create(velocityServer));
                server.getCommandManager().register(ServerCommand.create(server));
                
                // Register custom commands
                registerCustomCommands();
            }
        } catch (Exception e) {
            logger.error("Failed to register commands", e);
        }
    }
    
    private void registerCustomCommands() {
        // Register custom security and monitoring commands here
        // These will be created as needed
    }
    
    private void registerEventHandlers() {
        // Register event handlers here if needed
    }
    
    private void startServices() {
        try {
            if (configuration != null && configuration.isApiEnabled() && apiServer != null) {
                apiServer.start();
            }

            if (configuration != null && configuration.isMonitoringEnabled() && monitoringManager != null) {
                monitoringManager.start();
            }
        } catch (Exception e) {
            logger.error("Failed to start services", e);
        }
    }

    private void scheduleTasks() {
        // Update checker
        scheduler.scheduleWithFixedDelay(() -> {
            checkForUpdates();
        }, 1, 24, TimeUnit.HOURS);

        // Cleanup task
        scheduler.scheduleWithFixedDelay(() -> {
            performCleanup();
        }, 5, 5, TimeUnit.MINUTES);
    }

    private void checkForUpdates() {
        if (updateChecker != null) {
            updateChecker.checkForUpdates().thenAccept(updateAvailable -> {
                if (updateAvailable) {
                    notifyUpdateAvailable();
                }
            });
        }
    }

    private void notifyUpdateAvailable() {
        logger.info("A new version of Velocity is available!");
        
        Component message = Component.text()
            .content("A new version of Velocity is available!")
            .color(NamedTextColor.GREEN)
            .build();

        server.getAllPlayers().stream()
            .filter(player -> player.hasPermission("velocity.admin"))
            .forEach(player -> player.sendMessage(message));
    }

    private void performCleanup() {
        if (securityManager != null) {
            securityManager.cleanup();
        }
        if (monitoringManager != null) {
            monitoringManager.cleanup();
        }
        if (componentRegistry != null) {
            componentRegistry.cleanup();
        }
    }

    private void stopServices() {
        if (apiServer != null) {
            apiServer.stop();
        }

        if (monitoringManager != null) {
            monitoringManager.stop();
        }

        scheduler.shutdown();
    }

    private void saveData() {
        if (configuration != null) {
            configuration.save();
        }
        if (componentRegistry != null) {
            componentRegistry.saveData();
        }
        if (securityManager != null) {
            securityManager.saveData();
        }
    }

    private void cleanup() {
        try {
            scheduler.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // Getters
    public ProxyServer getServer() {
        return server;
    }

    public Logger getLogger() {
        return logger; 
    }

    public Path getDataDirectory() {
        return dataDirectory;
    }

    public VelocityConfiguration getConfiguration() {
        return configuration;
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public MonitoringManager getMonitoringManager() {
        return monitoringManager;
    }

    public ComponentRegistry getComponentRegistry() {
        return componentRegistry;
    }

    public CommandRegistry getCommandRegistry() {
        return commandRegistry;
    }

    public EventRegistry getEventRegistry() {
        return eventRegistry;
    }
}