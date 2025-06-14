package com.khoasoma.portableproxy;

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
import com.velocitypowered.api.ApiServer;
import com.velocitypowered.metrics.MetricsManager;
import com.velocitypowered.proxy.util.UpdateChecker;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

@Plugin(
    id = "project v11",
    name = "project v11",
    version = "2.0.0",
    url = "https://github.com/Khoasoma/PortableProxy",
    description = "Advanced Anti-DDoS Proxy with Dynamic Server Management",
    authors = {"Khoasoma"}
)
public class Velocity {
    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;
    
    // Managers
    private ConfigManager configManager;
    private ServerManager serverManager;
    private AntiDDoSManager antiDDoSManager;
    private PacketExploitManager packetExploitManager;
    private AntiBotManager antiBotManager;
    private MetricsManager metricsManager;
    
    // API Server
    private ApiServer apiServer;
    
    // Update checker
    private UpdateChecker updateChecker;

    @Inject
    public Velocity(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInitialization(ProxyInitializeEvent event) {
        // Initialize config first
        this.configManager = new ConfigManager(this);
        if (!configManager.loadConfig()) {
            logger.error("Failed to load configuration! Using default values.");
        }

        // Initialize protection managers
        initializeManagers();
        
        // Register event listeners
        registerEventListeners();
        
        // Register commands
        registerCommands();
        
        // Start API server if enabled
        if (configManager.getConfig().getApi().isEnabled()) {
            startApiServer();
        }
        
        // Start metrics if enabled
        if (configManager.getConfig().getMetrics().isEnabled()) {
            startMetrics();
        }
        
        // Schedule update checker
        scheduleUpdateChecker();
        
        // Initialize cleanup tasks
        scheduleCleanupTasks();

        logger.info("Proxy has been enabled! Version: 2.0.0");
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        // Cleanup and save data
        if (apiServer != null) {
            apiServer.stop();
        }
        
        if (metricsManager != null) {
            metricsManager.shutdown();
        }
        
        // Save any persistent data
        configManager.saveConfig();
        
        logger.info("Proxy has been disabled!");
    }

    private void initializeManagers() {
        this.serverManager = new ServerManager(this);
        this.antiDDoSManager = new AntiDDoSManager(this);
        this.packetExploitManager = new PacketExploitManager(this);
        this.antiBotManager = new AntiBotManager(this);
        this.metricsManager = new MetricsManager(this);
    }

    private void registerEventListeners() {
        server.getEventManager().register(this, antiDDoSManager);
        server.getEventManager().register(this, packetExploitManager);
        server.getEventManager().register(this, antiBotManager);
        server.getEventManager().register(this, serverManager);
    }

    private void registerCommands() {
        server.getCommandManager().register("proxy", new ProxyCommand(this), "pproxy", "portableproxy");
        server.getCommandManager().register("antibot", new AntiBotCommand(this));
        server.getCommandManager().register("antiddos", new AntiDDoSCommand(this));
        server.getCommandManager().register("server", new ServerCommand(this));
    }

    private void startApiServer() {
        try {
            this.apiServer = new ApiServer(this);
            apiServer.start();
        } catch (Exception e) {
            logger.error("Failed to start API server!", e);
        }
    }

    private void startMetrics() {
        try {
            metricsManager.start();
        } catch (Exception e) {
            logger.error("Failed to start metrics!", e);
        }
    }

    private void scheduleUpdateChecker() {
        this.updateChecker = new UpdateChecker(this);
        server.getScheduler()
            .buildTask(this, () -> {
                updateChecker.checkForUpdates().thenAccept(updateAvailable -> {
                    if (updateAvailable) {
                        logger.info("A new version of PortableProxy is available!");
                        // Notify online admins
                        server.getAllPlayers().stream()
                            .filter(player -> player.hasPermission("portableproxy.admin"))
                            .forEach(player -> player.sendMessage(
                                Component.text("A new version of PortableProxy is available!", 
                                NamedTextColor.GREEN)
                            ));
                    }
                });
            })
            .delay(1, TimeUnit.HOURS)
            .repeat(24, TimeUnit.HOURS)
            .schedule();
    }

    private void scheduleCleanupTasks() {
        // Schedule periodic cleanup tasks
        server.getScheduler()
            .buildTask(this, () -> {
                antiBotManager.cleanup();
                antiDDoSManager.cleanup();
                packetExploitManager.cleanup();
                metricsManager.cleanup();
            })
            .delay(5, TimeUnit.MINUTES)
            .repeat(5, TimeUnit.MINUTES)
            .schedule();
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

    public ConfigManager getConfigManager() {
        return configManager;
    }

    public ServerManager getServerManager() {
        return serverManager;
    }

    public AntiDDoSManager getAntiDDoSManager() {
        return antiDDoSManager;
    }

    public PacketExploitManager getPacketExploitManager() {
        return packetExploitManager;
    }

    public AntiBotManager getAntiBotManager() {
        return antiBotManager;
    }

    public MetricsManager getMetricsManager() {
        return metricsManager;
    }

    public ApiServer getApiServer() {
        return apiServer;
    }
}