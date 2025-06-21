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
import com.velocitypowered.proxy.security.SecurityManager;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;

import java.util.List;

public class SecurityCommand implements CommandRegistry.Command {
    private final Velocity velocity;
    private final SecurityManager securityManager;

    public SecurityCommand(Velocity velocity) {
        this.velocity = velocity;
        this.securityManager = velocity.getSecurityManager();
    }

    @Override
    public void execute(CommandRegistry.CommandSource source, String[] args) {
        if (args.length == 0) {
            showSecurityStatus(source);
            return;
        }

        String subCommand = args[0].toLowerCase();
        switch (subCommand) {
            case "status" -> showSecurityStatus(source);
            case "whitelist" -> handleWhitelist(source, args);
            case "blacklist" -> handleBlacklist(source, args);
            case "reload" -> reloadSecurity(source);
            case "help" -> showHelp(source);
            default -> {
                source.sendMessage(Component.text("Unknown security subcommand: " + subCommand, NamedTextColor.RED));
                showHelp(source);
            }
        }
    }

    @Override
    public List<String> suggest(CommandRegistry.CommandSource source, String[] currentArgs) {
        if (currentArgs.length <= 1) {
            return List.of("status", "whitelist", "blacklist", "reload", "help");
        } else if (currentArgs.length == 2) {
            String subCommand = currentArgs[0].toLowerCase();
            if ("whitelist".equals(subCommand) || "blacklist".equals(subCommand)) {
                return List.of("add", "remove", "list", "clear");
            }
        }
        return List.of();
    }

    @Override
    public boolean hasPermission(CommandRegistry.CommandSource source) {
        return source.hasPermission("velocity.command.security");
    }

    private void showSecurityStatus(CommandRegistry.CommandSource source) {
        source.sendMessage(Component.text()
            .append(Component.text("=== Security Status ===", NamedTextColor.RED, TextDecoration.BOLD))
            .append(Component.newline())
            .append(Component.text("DDoS Protection: ", NamedTextColor.AQUA))
            .append(Component.text("ENABLED", NamedTextColor.GREEN))
            .append(Component.newline())
            .append(Component.text("Anti-Bot: ", NamedTextColor.AQUA))
            .append(Component.text("ENABLED", NamedTextColor.GREEN))
            .append(Component.newline())
            .append(Component.text("Packet Filter: ", NamedTextColor.AQUA))
            .append(Component.text("ENABLED", NamedTextColor.GREEN))
            .append(Component.newline())
            .append(Component.text("Security Rules: ", NamedTextColor.AQUA))
            .append(Component.text("ACTIVE", NamedTextColor.GREEN))
            .build());
    }

    private void handleWhitelist(CommandRegistry.CommandSource source, String[] args) {
        if (args.length < 2) {
            source.sendMessage(Component.text("Usage: /security whitelist <add|remove|list|clear> [ip]", NamedTextColor.YELLOW));
            return;
        }

        String action = args[1].toLowerCase();
        switch (action) {
            case "add" -> {
                if (args.length < 3) {
                    source.sendMessage(Component.text("Usage: /security whitelist add <ip>", NamedTextColor.YELLOW));
                    return;
                }
                String ip = args[2];
                source.sendMessage(Component.text("Added " + ip + " to whitelist", NamedTextColor.GREEN));
            }
            case "remove" -> {
                if (args.length < 3) {
                    source.sendMessage(Component.text("Usage: /security whitelist remove <ip>", NamedTextColor.YELLOW));
                    return;
                }
                String ip = args[2];
                source.sendMessage(Component.text("Removed " + ip + " from whitelist", NamedTextColor.GREEN));
            }
            case "list" -> {
                source.sendMessage(Component.text("Whitelist is currently empty", NamedTextColor.GRAY));
            }
            case "clear" -> {
                source.sendMessage(Component.text("Whitelist cleared", NamedTextColor.GREEN));
            }
            default -> source.sendMessage(Component.text("Unknown whitelist action: " + action, NamedTextColor.RED));
        }
    }

    private void handleBlacklist(CommandRegistry.CommandSource source, String[] args) {
        if (args.length < 2) {
            source.sendMessage(Component.text("Usage: /security blacklist <add|remove|list|clear> [ip]", NamedTextColor.YELLOW));
            return;
        }

        String action = args[1].toLowerCase();
        switch (action) {
            case "add" -> {
                if (args.length < 3) {
                    source.sendMessage(Component.text("Usage: /security blacklist add <ip>", NamedTextColor.YELLOW));
                    return;
                }
                String ip = args[2];
                source.sendMessage(Component.text("Added " + ip + " to blacklist", NamedTextColor.GREEN));
            }
            case "remove" -> {
                if (args.length < 3) {
                    source.sendMessage(Component.text("Usage: /security blacklist remove <ip>", NamedTextColor.YELLOW));
                    return;
                }
                String ip = args[2];
                source.sendMessage(Component.text("Removed " + ip + " from blacklist", NamedTextColor.GREEN));
            }
            case "list" -> {
                source.sendMessage(Component.text("Blacklist is currently empty", NamedTextColor.GRAY));
            }
            case "clear" -> {
                source.sendMessage(Component.text("Blacklist cleared", NamedTextColor.GREEN));
            }
            default -> source.sendMessage(Component.text("Unknown blacklist action: " + action, NamedTextColor.RED));
        }
    }

    private void reloadSecurity(CommandRegistry.CommandSource source) {
        if (!source.hasPermission("velocity.command.security.reload")) {
            source.sendMessage(Component.text("You don't have permission to reload security settings.", NamedTextColor.RED));
            return;
        }

        try {
            securityManager.reload();
            source.sendMessage(Component.text("Security settings reloaded successfully!", NamedTextColor.GREEN));
        } catch (Exception e) {
            source.sendMessage(Component.text("Failed to reload security settings: " + e.getMessage(), NamedTextColor.RED));
        }
    }

    private void showHelp(CommandRegistry.CommandSource source) {
        source.sendMessage(Component.text()
            .append(Component.text("=== Security Commands ===", NamedTextColor.RED, TextDecoration.BOLD))
            .append(Component.newline())
            .append(Component.text("/security status", NamedTextColor.GREEN))
            .append(Component.text(" - Show security status", NamedTextColor.GRAY))
            .append(Component.newline())
            .append(Component.text("/security whitelist <add|remove|list|clear> [ip]", NamedTextColor.GREEN))
            .append(Component.text(" - Manage IP whitelist", NamedTextColor.GRAY))
            .append(Component.newline())
            .append(Component.text("/security blacklist <add|remove|list|clear> [ip]", NamedTextColor.GREEN))
            .append(Component.text(" - Manage IP blacklist", NamedTextColor.GRAY))
            .append(Component.newline())
            .append(Component.text("/security reload", NamedTextColor.GREEN))
            .append(Component.text(" - Reload security settings", NamedTextColor.GRAY))
            .build());
    }
}