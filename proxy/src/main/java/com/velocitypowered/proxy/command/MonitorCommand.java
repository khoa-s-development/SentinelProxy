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
 * Current Date and Time (UTC - YYYY-MM-DD HH:MM:SS formatted): 2025-06-21 12:11:26
 * Current User's Login: akk1to
 */

package com.velocitypowered.proxy.command;

import com.velocitypowered.proxy.Velocity;
import com.velocitypowered.proxy.CommandRegistry;
import com.velocitypowered.proxy.monitoring.MonitoringManager;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;

import java.util.List;

public class MonitorCommand implements CommandRegistry.Command {
    private final Velocity velocity;
    private final MonitoringManager monitoringManager;

    public MonitorCommand(Velocity velocity) {
        this.velocity = velocity;
        this.monitoringManager = velocity.getMonitoringManager();
    }

    @Override
    public void execute(CommandRegistry.CommandSource source, String[] args) {
        if (args.length == 0) {
            showMonitoringStatus(source);
            return;
        }

        String subCommand = args[0].toLowerCase();
        switch (subCommand) {
            case "status" -> showMonitoringStatus(source);
            case "stats" -> showDetailedStats(source);
            case "memory" -> showMemoryInfo(source);
            case "connections" -> showConnectionInfo(source);
            case "toggle" -> toggleMonitoring(source);
            case "help" -> showHelp(source);
            default -> {
                source.sendMessage(Component.text("Unknown monitor subcommand: " + subCommand, NamedTextColor.RED));
                showHelp(source);
            }
        }
    }

    @Override
    public List<String> suggest(CommandRegistry.CommandSource source, String[] currentArgs) {
        if (currentArgs.length <= 1) {
            return List.of("status", "stats", "memory", "connections", "toggle", "help");
        }
        return List.of();
    }

    @Override
    public boolean hasPermission(CommandRegistry.CommandSource source) {
        return source.hasPermission("velocity.command.monitor");
    }

    private void showMonitoringStatus(CommandRegistry.CommandSource source) {
        boolean enabled = monitoringManager.isEnabled();
        boolean running = monitoringManager.isRunning();

        source.sendMessage(Component.text()
            .append(Component.text("=== Monitoring Status ===", NamedTextColor.BLUE, TextDecoration.BOLD))
            .append(Component.newline())
            .append(Component.text("Monitoring: ", NamedTextColor.AQUA))
            .append(Component.text(enabled ? "ENABLED" : "DISABLED", enabled ? NamedTextColor.GREEN : NamedTextColor.RED))
            .append(Component.newline())
            .append(Component.text("Service: ", NamedTextColor.AQUA))
            .append(Component.text(running ? "RUNNING" : "STOPPED", running ? NamedTextColor.GREEN : NamedTextColor.RED))
            .append(Component.newline())
            .append(Component.text("Uptime: ", NamedTextColor.AQUA))
            .append(Component.text(monitoringManager.getUptimeMinutes() + " minutes", NamedTextColor.WHITE))
            .build());
    }

    private void showDetailedStats(CommandRegistry.CommandSource source) {
        long totalConnections = monitoringManager.getTotalConnections();
        long totalPackets = monitoringManager.getTotalPackets();
        long blockedConnections = monitoringManager.getBlockedConnections();
        int currentPlayers = velocity.getServer().getPlayerCount();

        source.sendMessage(Component.text()
            .append(Component.text("=== Detailed Statistics ===", NamedTextColor.BLUE, TextDecoration.BOLD))
            .append(Component.newline())
            .append(Component.text("Current Players: ", NamedTextColor.AQUA))
            .append(Component.text(String.valueOf(currentPlayers), NamedTextColor.WHITE))
            .append(Component.newline())
            .append(Component.text("Total Connections: ", NamedTextColor.AQUA))
            .append(Component.text(String.valueOf(totalConnections), NamedTextColor.WHITE))
            .append(Component.newline())
            .append(Component.text("Blocked Connections: ", NamedTextColor.AQUA))
            .append(Component.text(String.valueOf(blockedConnections), NamedTextColor.RED))
            .append(Component.newline())
            .append(Component.text("Total Packets: ", NamedTextColor.AQUA))
            .append(Component.text(String.valueOf(totalPackets), NamedTextColor.WHITE))
            .append(Component.newline())
            .append(Component.text("Block Rate: ", NamedTextColor.AQUA))
            .append(Component.text(String.format("%.2f%%", 
                totalConnections > 0 ? (double) blockedConnections / totalConnections * 100 : 0), 
                NamedTextColor.YELLOW))
            .build());
    }

    private void showMemoryInfo(CommandRegistry.CommandSource source) {
        long usedMemory = monitoringManager.getUsedMemoryMB();
        long maxMemory = monitoringManager.getMaxMemoryMB();
        double memoryPercent = monitoringManager.getMemoryUsagePercent();

        source.sendMessage(Component.text()
            .append(Component.text("=== Memory Information ===", NamedTextColor.BLUE, TextDecoration.BOLD))
            .append(Component.newline())
            .append(Component.text("Used Memory: ", NamedTextColor.AQUA))
            .append(Component.text(usedMemory + " MB", NamedTextColor.WHITE))
            .append(Component.newline())
            .append(Component.text("Max Memory: ", NamedTextColor.AQUA))
            .append(Component.text(maxMemory + " MB", NamedTextColor.WHITE))
            .append(Component.newline())
            .append(Component.text("Usage: ", NamedTextColor.AQUA))
            .append(Component.text(String.format("%.1f%%", memoryPercent), 
                memoryPercent > 80 ? NamedTextColor.RED : 
                memoryPercent > 60 ? NamedTextColor.YELLOW : NamedTextColor.GREEN))
            .append(Component.newline())
            .append(Component.text("Free Memory: ", NamedTextColor.AQUA))
            .append(Component.text((maxMemory - usedMemory) + " MB", NamedTextColor.WHITE))
            .build());
    }

    private void showConnectionInfo(CommandRegistry.CommandSource source) {
        int serverCount = velocity.getServer().getAllServers().size();
        source.sendMessage(Component.text()
            .append(Component.text("=== Connection Information ===", NamedTextColor.BLUE, TextDecoration.BOLD))
            .append(Component.newline())
            .append(Component.text("Registered Servers: ", NamedTextColor.AQUA))
            .append(Component.text(String.valueOf(serverCount), NamedTextColor.WHITE))
            .append(Component.newline())
            .append(Component.text("Active Connections: ", NamedTextColor.AQUA))
            .append(Component.text(String.valueOf(velocity.getServer().getPlayerCount()), NamedTextColor.WHITE))
            .build());

        // Show server details
        velocity.getServer().getAllServers().forEach(server -> {
            source.sendMessage(Component.text()
                .append(Component.text("  → ", NamedTextColor.GRAY))
                .append(Component.text(server.getServerInfo().getName(), NamedTextColor.YELLOW))
                .append(Component.text(" (", NamedTextColor.GRAY))
                .append(Component.text(String.valueOf(server.getPlayersConnected().size()), NamedTextColor.WHITE))
                .append(Component.text(" players)", NamedTextColor.GRAY))
                .build());
        });
    }

    private void toggleMonitoring(CommandRegistry.CommandSource source) {
        if (!source.hasPermission("velocity.command.monitor.toggle")) {
            source.sendMessage(Component.text("You don't have permission to toggle monitoring.", NamedTextColor.RED));
            return;
        }

        boolean currentState = monitoringManager.isEnabled();
        monitoringManager.setEnabled(!currentState);
        
        source.sendMessage(Component.text()
            .append(Component.text("Monitoring ", NamedTextColor.AQUA))
            .append(Component.text(!currentState ? "ENABLED" : "DISABLED", 
                !currentState ? NamedTextColor.GREEN : NamedTextColor.RED))
            .build());
    }

    private void showHelp(CommandRegistry.CommandSource source) {
        source.sendMessage(Component.text()
            .append(Component.text("=== Monitor Commands ===", NamedTextColor.BLUE, TextDecoration.BOLD))
            .append(Component.newline())
            .append(Component.text("/monitor status", NamedTextColor.GREEN))
            .append(Component.text(" - Show monitoring status", NamedTextColor.GRAY))
            .append(Component.newline())
            .append(Component.text("/monitor stats", NamedTextColor.GREEN))
            .append(Component.text(" - Show detailed statistics", NamedTextColor.GRAY))
            .append(Component.newline())
            .append(Component.text("/monitor memory", NamedTextColor.GREEN))
            .append(Component.text(" - Show memory information", NamedTextColor.GRAY))
            .append(Component.newline())
            .append(Component.text("/monitor connections", NamedTextColor.GREEN))
            .append(Component.text(" - Show connection information", NamedTextColor.GRAY))
            .append(Component.newline())
            .append(Component.text("/monitor toggle", NamedTextColor.GREEN))
            .append(Component.text(" - Toggle monitoring on/off", NamedTextColor.GRAY))
            .build());
    }
}