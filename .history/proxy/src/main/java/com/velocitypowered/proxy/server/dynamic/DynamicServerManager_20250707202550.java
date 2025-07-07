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

package com.velocitypowered.proxy.server.dynamic;

import com.velocitypowered.api.plugin.PluginContainer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.config.VelocityConfiguration;
import com.velocitypowered.proxy.server.ServerMap;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import com.electronwill.nightconfig.core.file.CommentedFileConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dynamic Server Manager.
 * Enables runtime management of Minecraft servers without proxy restarts.
 */
public class DynamicServerManager {
  
  private static final Logger logger = LoggerFactory.getLogger(DynamicServerManager.class);
  
  private final VelocityServer server;
  private final ServerMap serverMap;
  
  // Track server status and health information
  private final Map<String, ServerHealth> serverHealthMap = new ConcurrentHashMap<>();
  
  // For tracking dynamic servers
  private final Map<String, DynamicServerInfo> dynamicServers = new ConcurrentHashMap<>();
  
  // Server discovery and monitoring settings
  private final long healthCheckIntervalMs;
  private final int healthCheckTimeoutMs;
  private final int maxFailedChecks;
  
  /**
   * Creates a new dynamic server manager.
   *
   * @param server the Velocity server instance
   */
  public DynamicServerManager(VelocityServer server) {
    this(server, 30000, 5000, 3); // Default: check every 30s, timeout 5s, 3 failures to mark unhealthy
  }
  
  /**
   * Creates a new dynamic server manager with custom health check settings.
   *
   * @param server the Velocity server instance
   * @param healthCheckIntervalMs interval between health checks in milliseconds
   * @param healthCheckTimeoutMs timeout for health checks in milliseconds
   * @param maxFailedChecks maximum number of failed checks before marking a server unhealthy
   */
  public DynamicServerManager(VelocityServer server, long healthCheckIntervalMs,
                             int healthCheckTimeoutMs, int maxFailedChecks) {
    this.server = server;
    this.serverMap = server.getServerMap();
    this.healthCheckIntervalMs = healthCheckIntervalMs;
    this.healthCheckTimeoutMs = healthCheckTimeoutMs;
    this.maxFailedChecks = maxFailedChecks;
    
    logger.info("Dynamic Server Manager initialized");
    // Do not start health checker in constructor - will be started explicitly later
  }
  
  /**
   * Add a new server at runtime.
   *
   * @param name the server name
   * @param address the server address
   * @return true if the server was added, false if a server with that name already exists
   */
  public boolean addServer(String name, InetSocketAddress address) {
    if (serverMap.getServer(name).isPresent()) {
      logger.warn("Cannot add server {}: a server with that name already exists", name);
      return false;
    }
    
    ServerInfo info = new ServerInfo(name, address);
    RegisteredServer registeredServer = serverMap.register(info);
    
    // Track as a dynamic server
    dynamicServers.put(name, new DynamicServerInfo(name, address, System.currentTimeMillis()));
    
    // Initialize health tracking
    serverHealthMap.put(name, new ServerHealth());
    
    // Save the configuration to file
    boolean saved = saveConfigurationChanges();
    
    logger.info("Dynamically added server {} at {} (Config save: {})", 
        name, address, saved ? "successful" : "failed");
    return true;
  }
  
  /**
   * Add a new server at runtime.
   *
   * @param name the server name
   * @param hostname the server hostname
   * @param port the server port
   * @return true if the server was added, false if a server with that name already exists
   */
  public boolean addServer(String name, String hostname, int port) {
    return addServer(name, InetSocketAddress.createUnresolved(hostname, port));
  }
  
  /**
   * Remove a server at runtime.
   *
   * @param name the server name
   * @return true if the server was removed, false if the server doesn't exist
   */
  public boolean removeServer(String name) {
    if (!serverMap.containsServer(name)) {
      logger.warn("Cannot remove server {}: server doesn't exist", name);
      return false;
    }
    
    // Check if this is a static server (defined in the config)
    VelocityConfiguration config = server.getConfiguration();
    if (config.getServers().containsKey(name) && !dynamicServers.containsKey(name)) {
      logger.warn("Cannot remove server {}: it is defined in the configuration file", name);
      return false;
    }
    
    // Remove the server
    serverMap.unregister(name);
    dynamicServers.remove(name);
    serverHealthMap.remove(name);
    
    // Save the configuration to file
    boolean saved = saveConfigurationChanges();
    
    logger.info("Dynamically removed server {} (Config save: {})", 
        name, saved ? "successful" : "failed");
    return true;
  }
  
  /**
   * Get all servers registered with the proxy.
   *
   * @return a collection of all registered servers
   */
  public Collection<RegisteredServer> getAllServers() {
    return server.getAllServers();
  }
  
  /**
   * Get all dynamically added servers.
   *
   * @return a collection of dynamic server names
   */
  public Collection<String> getDynamicServers() {
    return dynamicServers.keySet();
  }
  
  /**
   * Get information about a dynamic server.
   *
   * @param name the server name
   * @return information about the dynamic server, or empty if not found
   */
  public Optional<DynamicServerInfo> getDynamicServerInfo(String name) {
    return Optional.ofNullable(dynamicServers.get(name));
  }
  
  /**
   * Get health status for a server.
   *
   * @param name the server name
   * @return the health status, or empty if the server doesn't exist
   */
  public Optional<ServerHealth> getServerHealth(String name) {
    return Optional.ofNullable(serverHealthMap.get(name));
  }
  
  /**
   * Check if a server is healthy (online and responding).
   *
   * @param name the server name
   * @return true if the server is healthy, false otherwise
   */
  public boolean isServerHealthy(String name) {
    ServerHealth health = serverHealthMap.get(name);
    return health != null && health.isHealthy();
  }
  
  /**
   * Check if a server exists.
   *
   * @param name the server name
   * @return true if the server exists, false otherwise
   */
  public boolean serverExists(String name) {
    return serverMap.containsServer(name);
  }
  
  /**
   * Update server address.
   * 
   * @param name the server name
   * @param newAddress the new server address
   * @return true if updated, false if server not found
   */
  public boolean updateServerAddress(String name, InetSocketAddress newAddress) {
    Optional<RegisteredServer> serverOpt = server.getServer(name);
    if (!serverOpt.isPresent()) {
      logger.warn("Cannot update server {}: server doesn't exist", name);
      return false;
    }
    
    // Velocity doesn't provide a direct way to update server info
    // So we need to remove and re-add the server
    boolean isDynamic = dynamicServers.containsKey(name);
    
    // Cannot update static servers
    if (!isDynamic) {
      logger.warn("Cannot update server {}: it is not a dynamic server", name);
      return false;
    }
    
    // Remove and re-add with new address
    removeServer(name);
    addServer(name, newAddress);
    
    logger.info("Updated server {} with new address: {}", name, newAddress);
    return true;
  }
  
  /**
   * Manually trigger a health check for a server.
   *
   * @param name the server name
   * @return a future that completes with the health check result
   */
  public CompletableFuture<Boolean> checkServerHealth(String name) {
    Optional<RegisteredServer> serverOpt = server.getServer(name);
    if (!serverOpt.isPresent()) {
      CompletableFuture<Boolean> future = new CompletableFuture<>();
      future.complete(false);
      return future;
    }
    
    RegisteredServer registeredServer = serverOpt.get();
    return performHealthCheck(name, registeredServer);
  }
  
  /**
   * Explicitly start the health checker.
   * This should be called after plugins are fully registered.
   *
   * @param plugin the plugin to associate the task with
   * @return true if health checker was started, false otherwise
   */
  public boolean startHealthChecker(PluginContainer plugin) {
    if (plugin == null) {
      logger.error("Cannot start health checker - plugin container is null");
      return false;
    }
    
    try {
      server.getScheduler().buildTask(plugin, this::checkAllServersHealth)
          .repeat(healthCheckIntervalMs, TimeUnit.MILLISECONDS)
          .schedule();
      
      logger.info("Server health checker started with interval: {}ms", healthCheckIntervalMs);
      return true;
    } catch (Exception e) {
      logger.error("Failed to start health checker", e);
      return false;
    }
  }
  
  /**
   * Start the background health checker.
   * @deprecated Use {@link #startHealthChecker(PluginContainer)} instead
   * This method is deprecated and should not be used as it can cause "plugin is not registered" errors.
   */
  @Deprecated
  private void startHealthChecker() {
    logger.warn("Deprecated startHealthChecker() called - use startHealthChecker(PluginContainer) instead");
    // Do nothing - this method is deprecated and should not be used
  }
  
  /**
   * Check health of all servers.
   */
  private void checkAllServersHealth() {
    logger.debug("Running health check for all servers");
    
    for (RegisteredServer registeredServer : server.getAllServers()) {
      String name = registeredServer.getServerInfo().getName();
      
      // Initialize health tracking if needed
      serverHealthMap.computeIfAbsent(name, k -> new ServerHealth());
      
      // Perform health check
      performHealthCheck(name, registeredServer);
    }
  }
  
  /**
   * Perform a health check on a single server.
   *
   * @param name server name
   * @param registeredServer the server to check
   * @return a future that completes with the health check result
   */
  private CompletableFuture<Boolean> performHealthCheck(String name, RegisteredServer registeredServer) {
    CompletableFuture<Boolean> result = new CompletableFuture<>();
    
    try {
      long startTime = System.currentTimeMillis();
      // Use ping to check if server is responsive
      registeredServer.ping().thenAccept(ping -> {
        // Server responded, mark as healthy
        ServerHealth health = serverHealthMap.get(name);
        if (health != null) {
          health.markHealthy();
          health.setLastResponseTimeMs(System.currentTimeMillis());
          health.setLastPingInfo(ping);
        }
        result.complete(true);
      }).exceptionally(ex -> {
        // Server didn't respond
        ServerHealth health = serverHealthMap.get(name);
        if (health != null) {
          health.markUnhealthy();
        }
        result.complete(false);
        return null;
      });
    } catch (Exception e) {
      logger.error("Error during health check for server {}: {}", name, e.getMessage());
      result.complete(false);
    }
    
    return result;
  }
  
  /**
   * Add a forced host entry.
   *
   * @param hostname the hostname
   * @param serverName the server name
   * @return true if the host was added, false if it already exists
   */
  public boolean addForcedHost(String hostname, String serverName) {
    VelocityConfiguration config = server.getConfiguration();
    Map<String, List<String>> forcedHosts = config.getForcedHosts();
    
    // Check if hostname already exists
    if (forcedHosts.containsKey(hostname)) {
      return false;
    }
    
    // Add new forced host
    List<String> serverList = new ArrayList<>();
    serverList.add(serverName);
    forcedHosts.put(hostname, serverList);
    
    // Save the configuration to file
    boolean saved = saveConfigurationChanges();
    
    logger.info("Added forced host: {} -> {} (Config save: {})", 
        hostname, serverName, saved ? "successful" : "failed");
    return true;
  }
  
  /**
   * Remove a forced host entry.
   *
   * @param hostname the hostname to remove
   * @return true if the host was removed, false if it didn't exist
   */
  public boolean removeForcedHost(String hostname) {
    VelocityConfiguration config = server.getConfiguration();
    Map<String, List<String>> forcedHosts = config.getForcedHosts();
    
    // Check if hostname exists
    if (!forcedHosts.containsKey(hostname)) {
      return false;
    }
    
    // Remove forced host
    forcedHosts.remove(hostname);
    
    // Save the configuration to file
    boolean saved = saveConfigurationChanges();
    
    logger.info("Removed forced host: {} (Config save: {})", 
        hostname, saved ? "successful" : "failed");
    return true;
  }
  
  /**
   * Get all forced hosts.
   *
   * @return map of hostnames to server lists
   */
  public Map<String, List<String>> getForcedHosts() {
    return server.getConfiguration().getForcedHosts();
  }
  
  /**
   * Get the Velocity server instance.
   *
   * @return the server instance
   */
  public VelocityServer getServer() {
    return server;
  }
  
  /**
   * Save the current configuration to file.
   * This writes the current state of forced hosts and servers to the velocity.toml file.
   * 
   * @return true if the save was successful, false otherwise
   */
  public boolean saveConfigurationChanges() {
    try {
      Path configPath = Path.of("velocity.toml");
      
      // If the config file doesn't exist, we can't save to it
      if (!Files.exists(configPath)) {
        logger.error("Cannot save configuration: velocity.toml does not exist");
        return false;
      }
      
      // Open the config file with NightConfig
      CommentedFileConfig config = CommentedFileConfig.builder(configPath).build();
      config.load();
      
      // Update the forced hosts section
      Map<String, List<String>> forcedHosts = server.getConfiguration().getForcedHosts();
      if (!forcedHosts.isEmpty()) {
        // Create a separate map that can be serialized correctly
        Map<String, Object> forcedHostsMap = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : forcedHosts.entrySet()) {
          forcedHostsMap.put(entry.getKey(), entry.getValue());
        }
        config.set("forced-hosts", forcedHostsMap);
      } else {
        // If no forced hosts, set an empty map
        config.set("forced-hosts", new HashMap<>());
      }
      
      // Update the servers section
      Map<String, String> serversMap = new HashMap<>();
      for (RegisteredServer server : getAllServers()) {
        ServerInfo info = server.getServerInfo();
        InetSocketAddress address = info.getAddress();
        serversMap.put(info.getName(), address.getHostString() + ":" + address.getPort());
      }
      config.set("servers", serversMap);
      
      // Save the config file
      config.save();
      logger.info("Saved configuration changes to velocity.toml");
      return true;
    } catch (Exception e) {
      logger.error("Failed to save configuration changes", e);
      return false;
    }
  }
  
  /**
   * Information about a dynamic server.
   */
  public static class DynamicServerInfo {
    private final String name;
    private final InetSocketAddress address;
    private final long createdTimeMs;
    
    public DynamicServerInfo(String name, InetSocketAddress address, long createdTimeMs) {
      this.name = name;
      this.address = address;
      this.createdTimeMs = createdTimeMs;
    }
    
    public String getName() {
      return name;
    }
    
    public InetSocketAddress getAddress() {
      return address;
    }
    
    public long getCreatedTimeMs() {
      return createdTimeMs;
    }
  }
  
  /**
   * Health tracking for a server.
   */
  public static class ServerHealth {
    private volatile boolean healthy = false;
    private volatile int failedChecks = 0;
    private volatile long lastResponseTimeMs = 0;
    private volatile Object lastPingInfo = null;
    
    public boolean isHealthy() {
      return healthy;
    }
    
    public void markHealthy() {
      this.healthy = true;
      this.failedChecks = 0;
    }
    
    public void markUnhealthy() {
      this.failedChecks++;
      if (this.failedChecks >= 3) { // 3 strikes and you're out
        this.healthy = false;
      }
    }
    
    public int getFailedChecks() {
      return failedChecks;
    }
    
    public long getLastResponseTimeMs() {
      return lastResponseTimeMs;
    }
    
    public void setLastResponseTimeMs(long lastResponseTimeMs) {
      this.lastResponseTimeMs = lastResponseTimeMs;
    }
    
    public Object getLastPingInfo() {
      return lastPingInfo;
    }
    
    public void setLastPingInfo(Object lastPingInfo) {
      this.lastPingInfo = lastPingInfo;
    }
  }
}

