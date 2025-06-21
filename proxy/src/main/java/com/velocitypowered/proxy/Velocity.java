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

package com.velocitypowered.proxy;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.proxy.command.*;
import com.velocitypowered.proxy.config.VelocityConfiguration;
import com.velocitypowered.proxy.protection.*;
import com.velocitypowered.proxy.security.SecurityManager;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import com.velocitypowered.proxy.monitoring.MonitoringManager;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
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
    private final VelocityConfiguration configuration;
    private final ComponentRegistry componentRegistry;
    private final CommandRegistry commandRegistry;
    private final EventRegistry eventRegistry; // Add this field

    // Protection components 
    private final SecurityManager securityManager;
    private final MonitoringManager monitoringManager;
    
    // Add missing fields
    private ApiServer apiServer;
    private UpdateChecker updateChecker;

    @Inject
    public Velocity(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
        this.scheduler = Executors.newScheduledThreadPool(4);

        // Initialize core components
        this.configuration = new VelocityConfiguration(dataDirectory);
        this.componentRegistry = new ComponentRegistry(this);
        this.commandRegistry = new CommandRegistry(this);
        this.eventRegistry = new EventRegistry(this); // Initialize this

        // Initialize protection components
        this.securityManager = new SecurityManager(this);
        this.monitoringManager = new MonitoringManager(this);
        
        // Initialize missing components
        this.apiServer = new ApiServer(this);
        this.updateChecker = new UpdateChecker(this);
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        try {
            // Load configuration
            configuration.load();

            // Initialize components
            initializeComponents();

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
        componentRegistry.initialize();
        securityManager.initialize();
        monitoringManager.initialize();
    }

    private void registerCommands() {
        commandRegistry.registerCommand("velocity", new VelocityCommand(this));
        commandRegistry.registerCommand("security", new SecurityCommand(this));
        commandRegistry.registerCommand("monitor", new MonitorCommand(this));
        commandRegistry.registerCommand("server", new ServerCommand(this));
    }
    
    private void registerEventHandlers() {
        // Add event handler registration if needed
    }
    
    private void startServices() {
        if (configuration.isApiEnabled()) {
            apiServer.start();
        }

        if (configuration.isMonitoringEnabled()) {
            monitoringManager.start();
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
        updateChecker.checkForUpdates().thenAccept(updateAvailable -> {
            if (updateAvailable) {
                notifyUpdateAvailable();
            }
        });
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
        securityManager.cleanup();
        monitoringManager.cleanup();
        componentRegistry.cleanup();
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
        configuration.save();
        componentRegistry.saveData();
        securityManager.saveData();
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