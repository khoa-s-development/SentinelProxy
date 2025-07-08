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

package com.velocitypowered.proxy.command.builtin;

import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.builder.RequiredArgumentBuilder;
import com.mojang.brigadier.arguments.BoolArgumentType;
import com.mojang.brigadier.tree.LiteralCommandNode;
import com.velocitypowered.api.command.BrigadierCommand;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.plugin.PluginContainer;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.connection.antiddos.AntiBot;
import com.velocitypowered.proxy.connection.antiddos.AntiBot.MiniWorldSession;
import com.velocitypowered.proxy.connection.antiddos.AntiBotConfig;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;

/**
 * Command to control and view information about the AntiBot system.
 */
public class AntiBotCommand {
    
    private static final Logger logger = LoggerFactory.getLogger(AntiBotCommand.class);
    private final VelocityServer server;
    
    public AntiBotCommand(VelocityServer server) {
        this.server = server;
    }
    
    /**
     * Create the command.
     *
     * @return the built command
     */
    public BrigadierCommand createCommand() {
        LiteralCommandNode<CommandSource> command = LiteralArgumentBuilder
            .<CommandSource>literal("antibot")
            .requires(source -> source.hasPermission("velocity.command.antibot"))
            .then(LiteralArgumentBuilder.<CommandSource>literal("status")
                .executes(ctx -> {
                    showStatus(ctx.getSource());
                    return 1;
                })
            )
            .then(LiteralArgumentBuilder.<CommandSource>literal("enable")
                .then(RequiredArgumentBuilder.<CommandSource, Boolean>argument("enabled", BoolArgumentType.bool())
                    .executes(ctx -> {
                        boolean enable = BoolArgumentType.getBool(ctx, "enabled");
                        toggleAntiBot(ctx.getSource(), enable);
                        return 1;
                    })
                )
            )
            .then(LiteralArgumentBuilder.<CommandSource>literal("check")
                .then(RequiredArgumentBuilder.<CommandSource, String>argument("player", com.mojang.brigadier.arguments.StringArgumentType.word())
                    .executes(ctx -> {
                        String playerName = com.mojang.brigadier.arguments.StringArgumentType.getString(ctx, "player");
                        checkPlayer(ctx.getSource(), playerName);
                        return 1;
                    })
                )
            )
            .then(LiteralArgumentBuilder.<CommandSource>literal("miniworld")
                .then(LiteralArgumentBuilder.<CommandSource>literal("check")
                    .then(RequiredArgumentBuilder.<CommandSource, String>argument("player", com.mojang.brigadier.arguments.StringArgumentType.word())
                        .executes(ctx -> {
                            String playerName = com.mojang.brigadier.arguments.StringArgumentType.getString(ctx, "player");
                            startMiniWorldCheck(ctx.getSource(), playerName);
                            return 1;
                        })
                    )
                )
                .then(LiteralArgumentBuilder.<CommandSource>literal("status")
                    .executes(ctx -> {
                        showMiniWorldStatus(ctx.getSource());
                        return 1;
                    })
                )
            )
            // New commands for advanced features
            .then(LiteralArgumentBuilder.<CommandSource>literal("ratelimit")
                .then(LiteralArgumentBuilder.<CommandSource>literal("status")
                    .executes(ctx -> {
                        showRateLimitStatus(ctx.getSource());
                        return 1;
                    })
                )
                .then(LiteralArgumentBuilder.<CommandSource>literal("enable")
                    .then(RequiredArgumentBuilder.<CommandSource, Boolean>argument("enabled", BoolArgumentType.bool())
                        .executes(ctx -> {
                            boolean enable = BoolArgumentType.getBool(ctx, "enabled");
                            toggleRateLimit(ctx.getSource(), enable);
                            return 1;
                        })
                    )
                )
            )
            .then(LiteralArgumentBuilder.<CommandSource>literal("pattern")
                .then(LiteralArgumentBuilder.<CommandSource>literal("status")
                    .executes(ctx -> {
                        showPatternStatus(ctx.getSource());
                        return 1;
                    })
                )
                .then(LiteralArgumentBuilder.<CommandSource>literal("enable")
                    .then(RequiredArgumentBuilder.<CommandSource, Boolean>argument("enabled", BoolArgumentType.bool())
                        .executes(ctx -> {
                            boolean enable = BoolArgumentType.getBool(ctx, "enabled");
                            togglePatternCheck(ctx.getSource(), enable);
                            return 1;
                        })
                    )
                )
                .then(LiteralArgumentBuilder.<CommandSource>literal("add")
                    .then(RequiredArgumentBuilder.<CommandSource, String>argument("pattern", com.mojang.brigadier.arguments.StringArgumentType.string())
                        .executes(ctx -> {
                            String pattern = com.mojang.brigadier.arguments.StringArgumentType.getString(ctx, "pattern");
                            addUsernamePattern(ctx.getSource(), pattern);
                            return 1;
                        })
                    )
                )
            )
            .then(LiteralArgumentBuilder.<CommandSource>literal("dns")
                .then(LiteralArgumentBuilder.<CommandSource>literal("status")
                    .executes(ctx -> {
                        showDnsStatus(ctx.getSource());
                        return 1;
                    })
                )
                .then(LiteralArgumentBuilder.<CommandSource>literal("enable")
                    .then(RequiredArgumentBuilder.<CommandSource, Boolean>argument("enabled", BoolArgumentType.bool())
                        .executes(ctx -> {
                            boolean enable = BoolArgumentType.getBool(ctx, "enabled");
                            toggleDnsCheck(ctx.getSource(), enable);
                            return 1;
                        })
                    )
                )
            )
            .then(LiteralArgumentBuilder.<CommandSource>literal("latency")
                .then(LiteralArgumentBuilder.<CommandSource>literal("status")
                    .executes(ctx -> {
                        showLatencyStatus(ctx.getSource());
                        return 1;
                    })
                )
                .then(LiteralArgumentBuilder.<CommandSource>literal("enable")
                    .then(RequiredArgumentBuilder.<CommandSource, Boolean>argument("enabled", BoolArgumentType.bool())
                        .executes(ctx -> {
                            boolean enable = BoolArgumentType.getBool(ctx, "enabled");
                            toggleLatencyCheck(ctx.getSource(), enable);
                            return 1;
                        })
                    )
                )
                .then(LiteralArgumentBuilder.<CommandSource>literal("setrange")
                    .then(RequiredArgumentBuilder.<CommandSource, Integer>argument("min", com.mojang.brigadier.arguments.IntegerArgumentType.integer(0))
                        .then(RequiredArgumentBuilder.<CommandSource, Integer>argument("max", com.mojang.brigadier.arguments.IntegerArgumentType.integer(1))
                            .executes(ctx -> {
                                int min = com.mojang.brigadier.arguments.IntegerArgumentType.getInteger(ctx, "min");
                                int max = com.mojang.brigadier.arguments.IntegerArgumentType.getInteger(ctx, "max");
                                setLatencyRange(ctx.getSource(), min, max);
                                return 1;
                            })
                        )
                    )
                )
            )
            .build();
        
        return new BrigadierCommand(command);
    }
    
    /**
     * Register this command on the server.
     */
    public void register() {
        // Get the virtual plugin instance which should be available
        Optional<PluginContainer> pluginOpt = server.getPluginManager().getPlugin("sentinalsproxy");
        
        if (!pluginOpt.isPresent()) {
            // Log error but try to continue using VelocityVirtualPlugin
            logger.error("Could not find sentinalsproxy plugin for AntiBot command registration");
            // Create a reference to the VelocityVirtualPlugin safely
            pluginOpt = server.getPluginManager().getPlugin("velocity");
            
            // If we can't find the velocity plugin either, we can't register the command
            if (!pluginOpt.isPresent()) {
                logger.error("Failed to find a suitable plugin for AntiBot command registration");
                return;
            }
        }
        
        PluginContainer plugin = pluginOpt.get();
        logger.info("Registering AntiBot command with plugin: {}", plugin.getDescription().getName());
        
        server.getCommandManager().register(
            server.getCommandManager().metaBuilder("antibot")
                .aliases("ab")
                .plugin(plugin)
                .build(),
            createCommand()
        );
        logger.info("AntiBot command registered successfully");
    }
    
    private void showStatus(CommandSource source) {
        AntiBot antiBot = server.getAntiBot();
        if (antiBot == null) {
            source.sendMessage(Component.text("AntiBot system is not enabled.", NamedTextColor.RED));
            return;
        }
        
        AntiBotConfig config = antiBot.getConfig();
        
        source.sendMessage(Component.text("==== AntiBot Status ====", NamedTextColor.GOLD)
                .decoration(TextDecoration.BOLD, true));
        
        // Main status
        source.sendMessage(Component.text("Enabled: ", NamedTextColor.YELLOW)
                .append(Component.text(antiBot.isEnabled(), 
                        antiBot.isEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        
        // Check status
        source.sendMessage(Component.text("Active Checks:", NamedTextColor.YELLOW));
        source.sendMessage(Component.text("- Gravity: ", NamedTextColor.GRAY)
                .append(Component.text(config.isGravityCheckEnabled(), 
                        config.isGravityCheckEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        source.sendMessage(Component.text("- Hitbox: ", NamedTextColor.GRAY)
                .append(Component.text(config.isHitboxCheckEnabled(), 
                        config.isHitboxCheckEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        source.sendMessage(Component.text("- Yaw/Rotation: ", NamedTextColor.GRAY)
                .append(Component.text(config.isYawCheckEnabled(), 
                        config.isYawCheckEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        source.sendMessage(Component.text("- Client Brand: ", NamedTextColor.GRAY)
                .append(Component.text(config.isClientBrandCheckEnabled(), 
                        config.isClientBrandCheckEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        source.sendMessage(Component.text("- Mini-world: ", NamedTextColor.GRAY)
                .append(Component.text(config.isMiniWorldCheckEnabled(), 
                        config.isMiniWorldCheckEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        // Add new features
        source.sendMessage(Component.text("- Rate Limit: ", NamedTextColor.GRAY)
                .append(Component.text(config.isRateLimitEnabled(), 
                        config.isRateLimitEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        source.sendMessage(Component.text("- Username Pattern: ", NamedTextColor.GRAY)
                .append(Component.text(config.isPatternCheckEnabled(), 
                        config.isPatternCheckEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        source.sendMessage(Component.text("- DNS Check: ", NamedTextColor.GRAY)
                .append(Component.text(config.isDnsCheckEnabled(), 
                        config.isDnsCheckEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        source.sendMessage(Component.text("- Latency Check: ", NamedTextColor.GRAY)
                .append(Component.text(config.isLatencyCheckEnabled(), 
                        config.isLatencyCheckEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        
        // Player statistics
        int verifiedCount = antiBot.getVerifiedPlayers().size();
        int totalPlayers = server.getPlayerCount();
        Map<UUID, MiniWorldSession> sessions = antiBot.getMiniWorldSessions();
        
        source.sendMessage(Component.text("Players:", NamedTextColor.YELLOW));
        source.sendMessage(Component.text("- Total Online: ", NamedTextColor.GRAY)
                .append(Component.text(totalPlayers, NamedTextColor.GREEN)));
        source.sendMessage(Component.text("- Verified: ", NamedTextColor.GRAY)
                .append(Component.text(verifiedCount, NamedTextColor.GREEN)));
        source.sendMessage(Component.text("- In Mini-world Check: ", NamedTextColor.GRAY)
                .append(Component.text(sessions.size(), NamedTextColor.AQUA)));
    }
    
    private void toggleAntiBot(CommandSource source, boolean enable) {
        AntiBot antiBot = server.getAntiBot();
        antiBot.setEnabled(enable);
        
        if (enable) {
            source.sendMessage(Component.text("AntiBot protection has been enabled.", NamedTextColor.GREEN));
        } else {
            source.sendMessage(Component.text("AntiBot protection has been disabled.", NamedTextColor.YELLOW));
        }
    }
    
    private void checkPlayer(CommandSource source, String playerName) {
        Optional<Player> playerOpt = server.getPlayer(playerName);
        if (playerOpt.isPresent()) {
            Player player = playerOpt.get();
            AntiBot antiBot = server.getAntiBot();
            
            source.sendMessage(Component.text("Manually checking player " + playerName + "...", NamedTextColor.YELLOW));
            
            boolean result = antiBot.checkPlayer(player);
            if (result) {
                source.sendMessage(Component.text("Player " + playerName + " passed all checks.", NamedTextColor.GREEN));
            } else {
                source.sendMessage(Component.text("Player " + playerName + " failed one or more checks!", NamedTextColor.RED));
            }
        } else {
            source.sendMessage(Component.text("Player " + playerName + " is not online.", NamedTextColor.RED));
        }
    }
    
    /**
     * Start a mini-world check for a specific player.
     *
     * @param source the command source
     * @param playerName the name of the player to check
     */
    private void startMiniWorldCheck(CommandSource source, String playerName) {
        Optional<Player> playerOpt = server.getPlayer(playerName);
        if (playerOpt.isPresent()) {
            Player player = playerOpt.get();
            AntiBot antiBot = server.getAntiBot();
            
            source.sendMessage(Component.text("Starting mini-world check for player " + playerName + "...", NamedTextColor.YELLOW));
            
            boolean result = antiBot.startMiniWorldCheck(player);
            if (result) {
                source.sendMessage(Component.text("Mini-world check started for " + playerName + ". Check status with /antibot miniworld status " + playerName, 
                    NamedTextColor.GREEN));
            } else {
                source.sendMessage(Component.text("Could not start mini-world check for " + playerName + ". Player might be already verified or checks disabled.", 
                    NamedTextColor.RED));
            }
        } else {
            source.sendMessage(Component.text("Player " + playerName + " is not online.", NamedTextColor.RED));
        }
    }
    
    /**
     * Check mini-world status for a specific player.
     *
     * @param source the command source
     * @param playerName the name of the player to check
     */
    private void checkMiniWorldStatus(CommandSource source, String playerName) {
        Optional<Player> playerOpt = server.getPlayer(playerName);
        if (playerOpt.isPresent()) {
            Player player = playerOpt.get();
            AntiBot antiBot = server.getAntiBot();
            UUID playerId = player.getUniqueId();
            
            if (antiBot.isInMiniWorldCheck(playerId)) {
                MiniWorldSession session = antiBot.getMiniWorldSession(playerId);
                
                if (session != null) {
                    source.sendMessage(Component.text("Mini-World Check Status for " + playerName + ":", NamedTextColor.GOLD, TextDecoration.BOLD));
                    source.sendMessage(Component.text("Time elapsed: ", NamedTextColor.YELLOW)
                        .append(Component.text(session.getElapsedSeconds() + "/" + antiBot.getConfig().getMiniWorldDuration() + " seconds", NamedTextColor.AQUA)));
                    source.sendMessage(Component.text("Movements: ", NamedTextColor.YELLOW)
                        .append(Component.text(session.movementCount + "/" + antiBot.getConfig().getMiniWorldMinMovements(), NamedTextColor.AQUA)));
                    source.sendMessage(Component.text("Distance moved: ", NamedTextColor.YELLOW)
                        .append(Component.text(String.format("%.2f", session.getDistanceMoved()) + " blocks", NamedTextColor.AQUA)));
                    source.sendMessage(Component.text("Has interacted: ", NamedTextColor.YELLOW)
                        .append(Component.text(session.hasInteracted() ? "Yes" : "No", session.hasInteracted() ? NamedTextColor.GREEN : NamedTextColor.RED)));
                    source.sendMessage(Component.text("Has jumped: ", NamedTextColor.YELLOW)
                        .append(Component.text(session.hasJumped() ? "Yes" : "No", session.hasJumped() ? NamedTextColor.GREEN : NamedTextColor.RED)));
                    source.sendMessage(Component.text("Status: ", NamedTextColor.YELLOW)
                        .append(Component.text(session.isCompleted() ? 
                            (session.isPassed() ? "PASSED" : "FAILED") : "IN PROGRESS", 
                            session.isCompleted() ? (session.isPassed() ? NamedTextColor.GREEN : NamedTextColor.RED) : NamedTextColor.YELLOW)));
                } else {
                    source.sendMessage(Component.text("Error: Mini-world session for " + playerName + " exists but could not be retrieved.", NamedTextColor.RED));
                }
            } else {
                if (antiBot.getVerifiedPlayers().contains(playerId)) {
                    source.sendMessage(Component.text("Player " + playerName + " is already verified and not in a mini-world check.", NamedTextColor.GREEN));
                } else {
                    source.sendMessage(Component.text("Player " + playerName + " is not currently in a mini-world check.", NamedTextColor.RED));
                }
            }
        } else {
            source.sendMessage(Component.text("Player " + playerName + " is not online.", NamedTextColor.RED));
        }
    }
    
    /**
     * Show mini-world status for all players.
     *
     * @param source the command source
     */
    private void showMiniWorldStatus(CommandSource source) {
        AntiBot antiBot = server.getAntiBot();
        Map<UUID, MiniWorldSession> sessions = antiBot.getMiniWorldSessions();
        
        source.sendMessage(Component.text("Mini-World Check Status:", NamedTextColor.GOLD, TextDecoration.BOLD));
        
        if (sessions.isEmpty()) {
            source.sendMessage(Component.text("No active mini-world sessions.", NamedTextColor.GRAY));
            return;
        }
        
        source.sendMessage(Component.text("Active sessions: " + sessions.size(), NamedTextColor.YELLOW));
        
        for (Map.Entry<UUID, MiniWorldSession> entry : sessions.entrySet()) {
            MiniWorldSession session = entry.getValue();
            UUID playerId = entry.getKey();
            
            // Try to get player name
            String playerName = server.getPlayer(playerId)
                .map(Player::getUsername)
                .orElse(playerId.toString().substring(0, 8));
            
            source.sendMessage(Component.text("- " + playerName + ": ", NamedTextColor.YELLOW)
                .append(Component.text(session.isCompleted() ? 
                    (session.isPassed() ? "PASSED" : "FAILED") : 
                    "IN PROGRESS (" + session.getElapsedSeconds() + "/" + antiBot.getConfig().getMiniWorldDuration() + " sec)", 
                    session.isCompleted() ? (session.isPassed() ? NamedTextColor.GREEN : NamedTextColor.RED) : NamedTextColor.AQUA)));
        }
    }
    
    /**
     * Format epoch time to readable date-time string.
     *
     * @param epoch the epoch time in milliseconds
     * @return the formatted date-time string
     */
    private String formatDateTime(long epoch) {
        java.util.Date date = new java.util.Date(epoch);
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return sdf.format(date);
    }
    
    /**
     * Show rate limit status.
     *
     * @param source the command source
     */
    private void showRateLimitStatus(CommandSource source) {
        AntiBot antiBot = server.getAntiBot();
        if (antiBot == null) {
            source.sendMessage(Component.text("AntiBot system is not enabled.", NamedTextColor.RED));
            return;
        }
        
        AntiBotConfig config = antiBot.getConfig();
        source.sendMessage(Component.text("==== AntiBot Rate Limiting Status ====", NamedTextColor.GOLD)
                .decoration(TextDecoration.BOLD, true));
        source.sendMessage(Component.text("Enabled: ", NamedTextColor.YELLOW)
                .append(Component.text(config.isRateLimitEnabled(), 
                        config.isRateLimitEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        source.sendMessage(Component.text("Threshold: ", NamedTextColor.YELLOW)
                .append(Component.text(config.getRateLimitThreshold(), NamedTextColor.AQUA))
                .append(Component.text(" connections per ", NamedTextColor.GRAY))
                .append(Component.text(config.getRateLimitWindowMillis() / 1000, NamedTextColor.AQUA))
                .append(Component.text(" seconds", NamedTextColor.GRAY)));
    }
    
    /**
     * Toggle rate limiting.
     *
     * @param source the command source
     * @param enable whether to enable rate limiting
     */
    private void toggleRateLimit(CommandSource source, boolean enable) {
        AntiBot antiBot = server.getAntiBot();
        if (antiBot == null) {
            source.sendMessage(Component.text("AntiBot system is not enabled.", NamedTextColor.RED));
            return;
        }
        
        // Create a new config with the updated setting
        AntiBotConfig oldConfig = antiBot.getConfig();
        AntiBotConfig newConfig = AntiBotConfig.builder()
                .enabled(oldConfig.isEnabled())
                .kickEnabled(oldConfig.isKickEnabled())
                .kickThreshold(oldConfig.getKickThreshold())
                .kickMessage(oldConfig.getKickMessage())
                .checkOnlyFirstJoin(oldConfig.isCheckOnlyFirstJoin())
                .verificationTimeout(oldConfig.getVerificationTimeout())
                .gravityCheckEnabled(oldConfig.isGravityCheckEnabled())
                .hitboxCheckEnabled(oldConfig.isHitboxCheckEnabled())
                .yawCheckEnabled(oldConfig.isYawCheckEnabled())
                .clientBrandCheckEnabled(oldConfig.isClientBrandCheckEnabled())
                .miniWorldCheckEnabled(oldConfig.isMiniWorldCheckEnabled())
                .miniWorldDuration(oldConfig.getMiniWorldDuration())
                .miniWorldMinMovements(oldConfig.getMiniWorldMinMovements())
                .miniWorldMinDistance(oldConfig.getMiniWorldMinDistance())
                .connectionRateLimitEnabled(enable)
                .build();
        
        // Apply the new config
        antiBot.configure(newConfig);
        
        source.sendMessage(Component.text("Rate limiting has been ", NamedTextColor.YELLOW)
                .append(Component.text(enable ? "enabled" : "disabled", 
                        enable ? NamedTextColor.GREEN : NamedTextColor.RED))
                .append(Component.text(".", NamedTextColor.YELLOW)));
    }
    
    /**
     * Show pattern check status.
     *
     * @param source the command source
     */
    private void showPatternStatus(CommandSource source) {
        AntiBot antiBot = server.getAntiBot();
        if (antiBot == null) {
            source.sendMessage(Component.text("AntiBot system is not enabled.", NamedTextColor.RED));
            return;
        }
        
        AntiBotConfig config = antiBot.getConfig();
        source.sendMessage(Component.text("==== AntiBot Username Pattern Status ====", NamedTextColor.GOLD)
                .decoration(TextDecoration.BOLD, true));
        source.sendMessage(Component.text("Enabled: ", NamedTextColor.YELLOW)
                .append(Component.text(config.isPatternCheckEnabled(), 
                        config.isPatternCheckEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        source.sendMessage(Component.text("Sequential Character Check: ", NamedTextColor.YELLOW)
                .append(Component.text(config.isSequentialCharCheck(), 
                        config.isSequentialCharCheck() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        source.sendMessage(Component.text("Random Distribution Check: ", NamedTextColor.YELLOW)
                .append(Component.text(config.isRandomDistributionCheck(), 
                        config.isRandomDistributionCheck() ? NamedTextColor.GREEN : NamedTextColor.RED)));
                
        // Show defined patterns
        source.sendMessage(Component.text("Defined Patterns:", NamedTextColor.YELLOW));
        for (String pattern : config.getUsernamePatterns()) {
            source.sendMessage(Component.text("- ", NamedTextColor.GRAY)
                    .append(Component.text(pattern, NamedTextColor.AQUA)));
        }
    }
    
    /**
     * Toggle pattern checking.
     *
     * @param source the command source
     * @param enable whether to enable pattern checking
     */
    private void togglePatternCheck(CommandSource source, boolean enable) {
        AntiBot antiBot = server.getAntiBot();
        if (antiBot == null) {
            source.sendMessage(Component.text("AntiBot system is not enabled.", NamedTextColor.RED));
            return;
        }
        
        // Create a new config with the updated setting
        AntiBotConfig oldConfig = antiBot.getConfig();
        AntiBotConfig newConfig = AntiBotConfig.builder()
                .enabled(oldConfig.isEnabled())
                .kickEnabled(oldConfig.isKickEnabled())
                .kickThreshold(oldConfig.getKickThreshold())
                .kickMessage(oldConfig.getKickMessage())
                .checkOnlyFirstJoin(oldConfig.isCheckOnlyFirstJoin())
                .verificationTimeout(oldConfig.getVerificationTimeout())
                .gravityCheckEnabled(oldConfig.isGravityCheckEnabled())
                .hitboxCheckEnabled(oldConfig.isHitboxCheckEnabled())
                .yawCheckEnabled(oldConfig.isYawCheckEnabled())
                .clientBrandCheckEnabled(oldConfig.isClientBrandCheckEnabled())
                .miniWorldCheckEnabled(oldConfig.isMiniWorldCheckEnabled())
                .usernamePatternCheckEnabled(enable)
                .build();
        
        // Apply the new config
        antiBot.configure(newConfig);
        
        source.sendMessage(Component.text("Username pattern checking has been ", NamedTextColor.YELLOW)
                .append(Component.text(enable ? "enabled" : "disabled", 
                        enable ? NamedTextColor.GREEN : NamedTextColor.RED))
                .append(Component.text(".", NamedTextColor.YELLOW)));
    }
    
    /**
     * Add a username pattern.
     *
     * @param source the command source
     * @param pattern the pattern to add
     */
    private void addUsernamePattern(CommandSource source, String pattern) {
        AntiBot antiBot = server.getAntiBot();
        if (antiBot == null) {
            source.sendMessage(Component.text("AntiBot system is not enabled.", NamedTextColor.RED));
            return;
        }
        
        try {
            // Test if the pattern is valid regex
            java.util.regex.Pattern.compile(pattern);
            
            // Create a new config with the added pattern
            AntiBotConfig oldConfig = antiBot.getConfig();
            AntiBotConfig.Builder builder = AntiBotConfig.builder()
                    .enabled(oldConfig.isEnabled())
                    .kickEnabled(oldConfig.isKickEnabled())
                    .kickThreshold(oldConfig.getKickThreshold())
                    .kickMessage(oldConfig.getKickMessage())
                    .checkOnlyFirstJoin(oldConfig.isCheckOnlyFirstJoin())
                    .verificationTimeout(oldConfig.getVerificationTimeout())
                    .gravityCheckEnabled(oldConfig.isGravityCheckEnabled())
                    .hitboxCheckEnabled(oldConfig.isHitboxCheckEnabled())
                    .yawCheckEnabled(oldConfig.isYawCheckEnabled())
                    .clientBrandCheckEnabled(oldConfig.isClientBrandCheckEnabled())
                    .miniWorldCheckEnabled(oldConfig.isMiniWorldCheckEnabled())
                    .usernamePatternCheckEnabled(oldConfig.isPatternCheckEnabled());
                    
            // Add existing patterns
            for (String existingPattern : oldConfig.getUsernamePatterns()) {
                builder.addUsernamePattern(existingPattern);
            }
            
            // Add the new pattern
            builder.addUsernamePattern(pattern);
            
            // Apply the new config
            antiBot.configure(builder.build());
            
            source.sendMessage(Component.text("Added pattern: ", NamedTextColor.YELLOW)
                    .append(Component.text(pattern, NamedTextColor.GREEN)));
        } catch (java.util.regex.PatternSyntaxException e) {
            source.sendMessage(Component.text("Invalid regex pattern: " + e.getMessage(), NamedTextColor.RED));
        }
    }
    
    /**
     * Show DNS check status.
     *
     * @param source the command source
     */
    private void showDnsStatus(CommandSource source) {
        AntiBot antiBot = server.getAntiBot();
        if (antiBot == null) {
            source.sendMessage(Component.text("AntiBot system is not enabled.", NamedTextColor.RED));
            return;
        }
        
        AntiBotConfig config = antiBot.getConfig();
        source.sendMessage(Component.text("==== AntiBot DNS Check Status ====", NamedTextColor.GOLD)
                .decoration(TextDecoration.BOLD, true));
        source.sendMessage(Component.text("Enabled: ", NamedTextColor.YELLOW)
                .append(Component.text(config.isDnsCheckEnabled(), 
                        config.isDnsCheckEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        source.sendMessage(Component.text("Allow Direct IP Connections: ", NamedTextColor.YELLOW)
                .append(Component.text(config.isAllowDirectIpConnections(), 
                        config.isAllowDirectIpConnections() ? NamedTextColor.GREEN : NamedTextColor.RED)));
                
        // Show allowed domains if any
        if (!config.getAllowedDomains().isEmpty()) {
            source.sendMessage(Component.text("Allowed Domains:", NamedTextColor.YELLOW));
            for (String domain : config.getAllowedDomains()) {
                source.sendMessage(Component.text("- ", NamedTextColor.GRAY)
                        .append(Component.text(domain, NamedTextColor.AQUA)));
            }
        } else {
            source.sendMessage(Component.text("Allowed Domains: ", NamedTextColor.YELLOW)
                    .append(Component.text("Any", NamedTextColor.GRAY)));
        }
        
        // Show excluded IPs
        source.sendMessage(Component.text("Excluded IPs:", NamedTextColor.YELLOW));
        for (String ip : config.getExcludedIps()) {
            source.sendMessage(Component.text("- ", NamedTextColor.GRAY)
                    .append(Component.text(ip, NamedTextColor.AQUA)));
        }
    }
    
    /**
     * Toggle DNS checking.
     *
     * @param source the command source
     * @param enable whether to enable DNS checking
     */
    private void toggleDnsCheck(CommandSource source, boolean enable) {
        AntiBot antiBot = server.getAntiBot();
        if (antiBot == null) {
            source.sendMessage(Component.text("AntiBot system is not enabled.", NamedTextColor.RED));
            return;
        }
        
        // Create a new config with the updated setting
        AntiBotConfig oldConfig = antiBot.getConfig();
        AntiBotConfig newConfig = AntiBotConfig.builder()
                .enabled(oldConfig.isEnabled())
                .kickEnabled(oldConfig.isKickEnabled())
                .kickThreshold(oldConfig.getKickThreshold())
                .kickMessage(oldConfig.getKickMessage())
                .checkOnlyFirstJoin(oldConfig.isCheckOnlyFirstJoin())
                .verificationTimeout(oldConfig.getVerificationTimeout())
                .gravityCheckEnabled(oldConfig.isGravityCheckEnabled())
                .hitboxCheckEnabled(oldConfig.isHitboxCheckEnabled())
                .yawCheckEnabled(oldConfig.isYawCheckEnabled())
                .clientBrandCheckEnabled(oldConfig.isClientBrandCheckEnabled())
                .miniWorldCheckEnabled(oldConfig.isMiniWorldCheckEnabled())
                .dnsCheckEnabled(enable)
                .build();
        
        // Apply the new config
        antiBot.configure(newConfig);
        
        source.sendMessage(Component.text("DNS checking has been ", NamedTextColor.YELLOW)
                .append(Component.text(enable ? "enabled" : "disabled", 
                        enable ? NamedTextColor.GREEN : NamedTextColor.RED))
                .append(Component.text(".", NamedTextColor.YELLOW)));
    }
    
    /**
     * Show latency check status.
     *
     * @param source the command source
     */
    private void showLatencyStatus(CommandSource source) {
        AntiBot antiBot = server.getAntiBot();
        if (antiBot == null) {
            source.sendMessage(Component.text("AntiBot system is not enabled.", NamedTextColor.RED));
            return;
        }
        
        AntiBotConfig config = antiBot.getConfig();
        source.sendMessage(Component.text("==== AntiBot Latency Check Status ====", NamedTextColor.GOLD)
                .decoration(TextDecoration.BOLD, true));
        source.sendMessage(Component.text("Enabled: ", NamedTextColor.YELLOW)
                .append(Component.text(config.isLatencyCheckEnabled(), 
                        config.isLatencyCheckEnabled() ? NamedTextColor.GREEN : NamedTextColor.RED)));
        source.sendMessage(Component.text("Min Latency: ", NamedTextColor.YELLOW)
                .append(Component.text(config.getMinLatencyThreshold(), NamedTextColor.AQUA))
                .append(Component.text(" ms", NamedTextColor.GRAY)));
        source.sendMessage(Component.text("Max Latency: ", NamedTextColor.YELLOW)
                .append(Component.text(config.getMaxLatencyThreshold(), NamedTextColor.AQUA))
                .append(Component.text(" ms", NamedTextColor.GRAY)));
    }
    
    /**
     * Toggle latency checking.
     *
     * @param source the command source
     * @param enable whether to enable latency checking
     */
    private void toggleLatencyCheck(CommandSource source, boolean enable) {
        AntiBot antiBot = server.getAntiBot();
        if (antiBot == null) {
            source.sendMessage(Component.text("AntiBot system is not enabled.", NamedTextColor.RED));
            return;
        }
        
        // Create a new config with the updated setting
        AntiBotConfig oldConfig = antiBot.getConfig();
        AntiBotConfig newConfig = AntiBotConfig.builder()
                .enabled(oldConfig.isEnabled())
                .kickEnabled(oldConfig.isKickEnabled())
                .kickThreshold(oldConfig.getKickThreshold())
                .kickMessage(oldConfig.getKickMessage())
                .checkOnlyFirstJoin(oldConfig.isCheckOnlyFirstJoin())
                .verificationTimeout(oldConfig.getVerificationTimeout())
                .gravityCheckEnabled(oldConfig.isGravityCheckEnabled())
                .hitboxCheckEnabled(oldConfig.isHitboxCheckEnabled())
                .yawCheckEnabled(oldConfig.isYawCheckEnabled())
                .clientBrandCheckEnabled(oldConfig.isClientBrandCheckEnabled())
                .miniWorldCheckEnabled(oldConfig.isMiniWorldCheckEnabled())
                .latencyCheckEnabled(enable)
                .build();
        
        // Apply the new config
        antiBot.configure(newConfig);
        
        source.sendMessage(Component.text("Latency checking has been ", NamedTextColor.YELLOW)
                .append(Component.text(enable ? "enabled" : "disabled", 
                        enable ? NamedTextColor.GREEN : NamedTextColor.RED))
                .append(Component.text(".", NamedTextColor.YELLOW)));
    }
    
    /**
     * Set the latency range for checks.
     *
     * @param source the command source
     * @param min minimum latency in ms
     * @param max maximum latency in ms
     */
    private void setLatencyRange(CommandSource source, int min, int max) {
        AntiBot antiBot = server.getAntiBot();
        if (antiBot == null) {
            source.sendMessage(Component.text("AntiBot system is not enabled.", NamedTextColor.RED));
            return;
        }
        
        if (min >= max) {
            source.sendMessage(Component.text("Error: Min latency must be less than max latency.", NamedTextColor.RED));
            return;
        }
        
        // Create a new config with the updated setting
        AntiBotConfig oldConfig = antiBot.getConfig();
        AntiBotConfig newConfig = AntiBotConfig.builder()
                .enabled(oldConfig.isEnabled())
                .kickEnabled(oldConfig.isKickEnabled())
                .kickThreshold(oldConfig.getKickThreshold())
                .kickMessage(oldConfig.getKickMessage())
                .checkOnlyFirstJoin(oldConfig.isCheckOnlyFirstJoin())
                .verificationTimeout(oldConfig.getVerificationTimeout())
                .gravityCheckEnabled(oldConfig.isGravityCheckEnabled())
                .hitboxCheckEnabled(oldConfig.isHitboxCheckEnabled())
                .yawCheckEnabled(oldConfig.isYawCheckEnabled())
                .clientBrandCheckEnabled(oldConfig.isClientBrandCheckEnabled())
                .miniWorldCheckEnabled(oldConfig.isMiniWorldCheckEnabled())
                .latencyCheckEnabled(oldConfig.isLatencyCheckEnabled())
                .minLatencyThreshold(min)
                .maxLatencyThreshold(max)
                .build();
        
        // Apply the new config
        antiBot.configure(newConfig);
        
        source.sendMessage(Component.text("Latency range set to ", NamedTextColor.YELLOW)
                .append(Component.text(min, NamedTextColor.GREEN))
                .append(Component.text(" - ", NamedTextColor.GRAY))
                .append(Component.text(max, NamedTextColor.GREEN))
                .append(Component.text(" ms", NamedTextColor.YELLOW)));
    }
}
