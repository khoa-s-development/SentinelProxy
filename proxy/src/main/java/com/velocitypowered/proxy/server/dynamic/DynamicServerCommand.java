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

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.permission.Tristate;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;

/**
 * Command handler for dynamic server management.
 */
public class DynamicServerCommand implements SimpleCommand {

  private final DynamicServerManager manager;

  public DynamicServerCommand(DynamicServerManager manager) {
    this.manager = manager;
  }

  @Override
  public void execute(final SimpleCommand.Invocation invocation) {
    CommandSource source = invocation.source();
    String[] args = invocation.arguments();
    if (args.length == 0) {
      showHelp(source);
      return;
    }

    String subcommand = args[0].toLowerCase();
    
    switch (subcommand) {
      case "list":
        listServers(source);
        break;
        
      case "add":
        if (args.length < 4) {
          source.sendMessage(Component.text(
              "Usage: /server add <name> <host> <port>", NamedTextColor.RED));
          return;
        }
        addServer(source, args[1], args[2], parsePort(args[3]));
        break;
        
      case "remove":
        if (args.length < 2) {
          source.sendMessage(Component.text(
              "Usage: /server remove <name>", NamedTextColor.RED));
          return;
        }
        removeServer(source, args[1]);
        break;
        
      case "check":
        if (args.length < 2) {
          source.sendMessage(Component.text(
              "Usage: /server check <name>", NamedTextColor.RED));
          return;
        }
        checkServer(source, args[1]);
        break;
        
      case "info":
        if (args.length < 2) {
          source.sendMessage(Component.text(
              "Usage: /server info <name>", NamedTextColor.RED));
          return;
        }
        showServerInfo(source, args[1]);
        break;
        
      case "update":
        if (args.length < 4) {
          source.sendMessage(Component.text(
              "Usage: /server update <name> <newhost> <newport>", NamedTextColor.RED));
          return;
        }
        updateServer(source, args[1], args[2], parsePort(args[3]));
        break;
        
      case "addalias":
      case "host":
        if (args.length < 3) {
          source.sendMessage(Component.text(
              "Usage: /dserver addalias <hostname> <server>", NamedTextColor.RED));
          return;
        }
        addForcedHost(source, args[1], args[2]);
        break;
        
      case "removealias":
      case "removehost":
        if (args.length < 2) {
          source.sendMessage(Component.text(
              "Usage: /dserver removealias <hostname>", NamedTextColor.RED));
          return;
        }
        removeForcedHost(source, args[1]);
        break;
        
      case "aliases":
      case "hosts":
        listForcedHosts(source);
        break;
        
      case "help":
      default:
        showHelp(source);
        break;
    }
  }

  @Override
  public List<String> suggest(final SimpleCommand.Invocation invocation) {
    CommandSource source = invocation.source();
    String[] currentArgs = invocation.arguments();
    if (currentArgs.length == 0 || currentArgs.length == 1) {
      return Arrays.asList("list", "add", "remove", "check", "info", "update", "addalias", 
          "removealias", "aliases", "hosts", "help");
    }
    
    String subcommand = currentArgs[0].toLowerCase();
    
    if (currentArgs.length == 2) {
      if ("remove".equals(subcommand) || "check".equals(subcommand) || 
          "info".equals(subcommand) || "update".equals(subcommand)) {
        // Return list of server names for these commands
        return manager.getAllServers().stream()
            .map(server -> server.getServerInfo().getName())
            .collect(Collectors.toList());
      } else if ("addalias".equals(subcommand) || "host".equals(subcommand)) {
        // For addalias, second argument is hostname, no completion
        return new ArrayList<>();
      } else if ("removealias".equals(subcommand) || "removehost".equals(subcommand)) {
        // Return list of forced hosts
        return new ArrayList<>(manager.getServer().getConfiguration().getForcedHosts().keySet());
      }
    } else if (currentArgs.length == 3) {
      if ("addalias".equals(subcommand) || "host".equals(subcommand)) {
        // Third argument is server name
        return manager.getAllServers().stream()
            .map(server -> server.getServerInfo().getName())
            .collect(Collectors.toList());
      }
    }
    
    return new ArrayList<>();
  }

  @Override
  public boolean hasPermission(final SimpleCommand.Invocation invocation) {
    CommandSource source = invocation.source();
    if (source.getPermissionValue("velocity.command.server.admin") == Tristate.TRUE) {
      return true;
    }
    
    return false;
  }
  
  private void showHelp(CommandSource source) {
    source.sendMessage(Component.text("Dynamic Server Management Commands:", NamedTextColor.GOLD));
    source.sendMessage(Component.text("  /dserver list - List all registered servers", NamedTextColor.YELLOW));
    source.sendMessage(Component.text("  /dserver add <name> <host> <port> - Add a new server (saves to config)", NamedTextColor.YELLOW));
    source.sendMessage(Component.text("  /dserver remove <name> - Remove a server (saves to config)", NamedTextColor.YELLOW));
    source.sendMessage(Component.text("  /dserver check <name> - Check server health", NamedTextColor.YELLOW));
    source.sendMessage(Component.text("  /dserver info <name> - Show detailed server info", NamedTextColor.YELLOW));
    source.sendMessage(Component.text("  /dserver update <name> <newhost> <newport> - Update server address", NamedTextColor.YELLOW));
    source.sendMessage(Component.text("  /dserver addalias <hostname> <server> - Add a host alias (saves to config)", NamedTextColor.YELLOW));
    source.sendMessage(Component.text("  /dserver removealias <hostname> - Remove a host alias (saves to config)", NamedTextColor.YELLOW));
    source.sendMessage(Component.text("  /dserver aliases - List all host aliases", NamedTextColor.YELLOW));
    source.sendMessage(Component.text("Note: Changes made with these commands are saved to velocity.toml", NamedTextColor.AQUA));
  }
  
  private void listServers(CommandSource source) {
    Collection<RegisteredServer> allServers = manager.getAllServers();
    Collection<String> dynamicServers = manager.getDynamicServers();
    
    source.sendMessage(Component.text("Registered Servers (" + allServers.size() + "):", NamedTextColor.GOLD));
    
    for (RegisteredServer server : allServers) {
      String name = server.getServerInfo().getName();
      String address = server.getServerInfo().getAddress().toString();
      boolean isDynamic = dynamicServers.contains(name);
      boolean isHealthy = manager.isServerHealthy(name);
      
      Component serverInfo = Component.text("  " + name + " - ", 
          isDynamic ? NamedTextColor.AQUA : NamedTextColor.YELLOW)
          .append(Component.text(address, NamedTextColor.WHITE))
          .append(Component.text(" [", NamedTextColor.GRAY))
          .append(Component.text(isDynamic ? "Dynamic" : "Static", 
              isDynamic ? NamedTextColor.AQUA : NamedTextColor.YELLOW))
          .append(Component.text("] [", NamedTextColor.GRAY))
          .append(Component.text(isHealthy ? "Online" : "Offline", 
              isHealthy ? NamedTextColor.GREEN : NamedTextColor.RED))
          .append(Component.text("]", NamedTextColor.GRAY));
      
      source.sendMessage(serverInfo);
    }
  }
  
  private void addServer(CommandSource source, String name, String host, int port) {
    if (port <= 0 || port > 65535) {
      source.sendMessage(Component.text("Invalid port number. Must be between 1-65535.", NamedTextColor.RED));
      return;
    }
    
    boolean success = manager.addServer(name, host, port);
    
    if (success) {
      source.sendMessage(Component.text(
          "Server " + name + " added successfully at " + host + ":" + port, 
          NamedTextColor.GREEN));
    } else {
      source.sendMessage(Component.text(
          "Failed to add server. A server with that name may already exist.", 
          NamedTextColor.RED));
    }
  }
  
  private void removeServer(CommandSource source, String name) {
    boolean success = manager.removeServer(name);
    
    if (success) {
      source.sendMessage(Component.text(
          "Server " + name + " removed successfully.", 
          NamedTextColor.GREEN));
    } else {
      source.sendMessage(Component.text(
          "Failed to remove server. The server may not exist or might be a static server.", 
          NamedTextColor.RED));
    }
  }
  
  private void checkServer(CommandSource source, String name) {
    if (!manager.serverExists(name)) {
      source.sendMessage(Component.text(
          "Server " + name + " does not exist.", 
          NamedTextColor.RED));
      return;
    }
    
    source.sendMessage(Component.text(
        "Checking health of server " + name + "...", 
        NamedTextColor.YELLOW));
    
    manager.checkServerHealth(name).thenAccept(healthy -> {
      if (healthy) {
        source.sendMessage(Component.text(
            "Server " + name + " is online and healthy.", 
            NamedTextColor.GREEN));
      } else {
        source.sendMessage(Component.text(
            "Server " + name + " is offline or not responding.", 
            NamedTextColor.RED));
      }
    });
  }
  
  private void showServerInfo(CommandSource source, String name) {
    if (!manager.serverExists(name)) {
      source.sendMessage(Component.text(
          "Server " + name + " does not exist.", 
          NamedTextColor.RED));
      return;
    }
    
    // Get server info
    Optional<RegisteredServer> serverOpt = manager.getAllServers().stream()
        .filter(server -> server.getServerInfo().getName().equals(name))
        .findFirst();
    
    if (!serverOpt.isPresent()) {
      source.sendMessage(Component.text(
          "Failed to get server information.", 
          NamedTextColor.RED));
      return;
    }
    
    RegisteredServer server = serverOpt.get();
    boolean isDynamic = manager.getDynamicServers().contains(name);
    boolean isHealthy = manager.isServerHealthy(name);
    
    // Get health info
    Optional<DynamicServerManager.ServerHealth> healthOpt = manager.getServerHealth(name);
    
    source.sendMessage(Component.text("Server Information: " + name, NamedTextColor.GOLD));
    source.sendMessage(Component.text("  Address: " + server.getServerInfo().getAddress(), NamedTextColor.YELLOW));
    source.sendMessage(Component.text("  Type: " + (isDynamic ? "Dynamic" : "Static"), NamedTextColor.YELLOW));
    source.sendMessage(Component.text("  Status: " + (isHealthy ? "Online" : "Offline"), 
        isHealthy ? NamedTextColor.GREEN : NamedTextColor.RED));
    
    if (healthOpt.isPresent()) {
      DynamicServerManager.ServerHealth health = healthOpt.get();
      source.sendMessage(Component.text("  Failed checks: " + health.getFailedChecks(), NamedTextColor.YELLOW));
      source.sendMessage(Component.text("  Last response: " + formatTime(health.getLastResponseTimeMs()), NamedTextColor.YELLOW));
    }
    
    // Player count
    int playerCount = server.getPlayersConnected().size();
    source.sendMessage(Component.text("  Players: " + playerCount, NamedTextColor.YELLOW));
    
    // Show players if any
    if (playerCount > 0) {
      String players = server.getPlayersConnected().stream()
          .map(Player::getUsername)
          .collect(Collectors.joining(", "));
      source.sendMessage(Component.text("  Player list: " + players, NamedTextColor.YELLOW));
    }
    
    // Show dynamic server info
    if (isDynamic) {
      Optional<DynamicServerManager.DynamicServerInfo> dynamicInfoOpt = 
          manager.getDynamicServerInfo(name);
      
      if (dynamicInfoOpt.isPresent()) {
        DynamicServerManager.DynamicServerInfo dynamicInfo = dynamicInfoOpt.get();
        long createdTime = dynamicInfo.getCreatedTimeMs();
        long uptimeMs = System.currentTimeMillis() - createdTime;
        
        source.sendMessage(Component.text("  Added: " + formatTime(createdTime), NamedTextColor.AQUA));
        source.sendMessage(Component.text("  Uptime: " + formatDuration(uptimeMs), NamedTextColor.AQUA));
      }
    }
  }
  
  private void updateServer(CommandSource source, String name, String newHost, int newPort) {
    if (newPort <= 0 || newPort > 65535) {
      source.sendMessage(Component.text("Invalid port number. Must be between 1-65535.", NamedTextColor.RED));
      return;
    }
    
    InetSocketAddress newAddress = InetSocketAddress.createUnresolved(newHost, newPort);
    boolean success = manager.updateServerAddress(name, newAddress);
    
    if (success) {
      source.sendMessage(Component.text(
          "Server " + name + " updated successfully to " + newHost + ":" + newPort, 
          NamedTextColor.GREEN));
    } else {
      source.sendMessage(Component.text(
          "Failed to update server. The server may not exist or might be a static server.", 
          NamedTextColor.RED));
    }
  }
  
  /**
   * Add a forced host (hostname alias) for a server.
   *
   * @param source the command source
   * @param hostname the hostname to add
   * @param serverName the server to associate with the hostname
   */
  private void addForcedHost(CommandSource source, String hostname, String serverName) {
    // Check if server exists
    Optional<RegisteredServer> server = manager.getServer().getServer(serverName);
    if (!server.isPresent()) {
      source.sendMessage(Component.text(
          "Server " + serverName + " does not exist.", 
          NamedTextColor.RED));
      return;
    }
    
    // Add forced host
    boolean success = manager.addForcedHost(hostname, serverName);
    
    if (success) {
      // Get the server binding information to show the complete connection info
      String bindAddress = manager.getServer().getConfiguration().getBind().getHostString();
      if (bindAddress.equals("0.0.0.0")) {
        bindAddress = "your-server-ip"; // Generic placeholder for any-address binding
      }
      
      source.sendMessage(Component.text("Added hostname alias:", NamedTextColor.GREEN));
      source.sendMessage(Component.text("  " + hostname + " → " + serverName, NamedTextColor.GREEN));
      source.sendMessage(Component.text("Players can connect using: ", NamedTextColor.AQUA)
          .append(Component.text(hostname, NamedTextColor.WHITE)));
      source.sendMessage(Component.text("Configuration saved to velocity.toml", NamedTextColor.GREEN));
    } else {
      source.sendMessage(Component.text(
          "Failed to add hostname alias. It may already exist.", 
          NamedTextColor.RED));
    }
  }
  
  /**
   * Remove a forced host (hostname alias).
   *
   * @param source the command source
   * @param hostname the hostname to remove
   */
  private void removeForcedHost(CommandSource source, String hostname) {
    boolean success = manager.removeForcedHost(hostname);
    
    if (success) {
      source.sendMessage(Component.text(
          "Removed hostname alias: " + hostname, 
          NamedTextColor.GREEN));
    } else {
      source.sendMessage(Component.text(
          "No such hostname alias: " + hostname, 
          NamedTextColor.RED));
    }
  }
  
  /**
   * List all forced hosts (hostname aliases).
   *
   * @param source the command source
   */
  private void listForcedHosts(CommandSource source) {
    Map<String, List<String>> forcedHosts = manager.getForcedHosts();
    
    source.sendMessage(Component.text("Hostname Aliases (" + forcedHosts.size() + "):", NamedTextColor.GOLD));
    
    if (forcedHosts.isEmpty()) {
      source.sendMessage(Component.text("  No hostname aliases configured.", NamedTextColor.GRAY));
    } else {
      forcedHosts.forEach((hostname, servers) -> {
        Component hostInfo = Component.text("  " + hostname + " → ", NamedTextColor.YELLOW)
            .append(Component.text(String.join(", ", servers), NamedTextColor.WHITE));
        source.sendMessage(hostInfo);
      });
    }
  }
  
  private int parsePort(String portStr) {
    try {
      return Integer.parseInt(portStr);
    } catch (NumberFormatException e) {
      return -1;
    }
  }
  
  private String formatTime(long timeMs) {
    if (timeMs == 0) {
      return "never";
    }
    
    // Return something like "5 minutes ago" or "just now"
    long diff = System.currentTimeMillis() - timeMs;
    if (diff < 0) {
      return "in the future (check system clock)";
    } else if (diff < 1000) {
      return "just now";
    } else if (diff < 60000) {
      return (diff / 1000) + " seconds ago";
    } else if (diff < 3600000) {
      return (diff / 60000) + " minutes ago";
    } else if (diff < 86400000) {
      return (diff / 3600000) + " hours ago";
    } else {
      return (diff / 86400000) + " days ago";
    }
  }
  
  private String formatDuration(long durationMs) {
    if (durationMs < 1000) {
      return durationMs + "ms";
    } else if (durationMs < 60000) {
      return TimeUnit.MILLISECONDS.toSeconds(durationMs) + "s";
    } else if (durationMs < 3600000) {
      long minutes = TimeUnit.MILLISECONDS.toMinutes(durationMs);
      long seconds = TimeUnit.MILLISECONDS.toSeconds(durationMs) % 60;
      return minutes + "m " + seconds + "s";
    } else if (durationMs < 86400000) {
      long hours = TimeUnit.MILLISECONDS.toHours(durationMs);
      long minutes = TimeUnit.MILLISECONDS.toMinutes(durationMs) % 60;
      return hours + "h " + minutes + "m";
    } else {
      long days = TimeUnit.MILLISECONDS.toDays(durationMs);
      long hours = TimeUnit.MILLISECONDS.toHours(durationMs) % 24;
      return days + "d " + hours + "h";
    }
  }
}
