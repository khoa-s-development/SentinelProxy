/*
 * Copyright (C) 2018-2023 Velocity Contributors
 *
 * Current Date and Time (UTC - YYYY-MM-DD HH:MM:SS formatted): 2025-06-15 13:38:06
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.command;

import com.google.common.base.Preconditions;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CommandRegistry {
    private static final Logger logger = LogManager.getLogger(CommandRegistry.class);
    private final Map<String, Command> commands = new HashMap<>();

    /**
     * Interface for command sources that can execute commands.
     */
    public interface CommandSource {
        void sendMessage(Component message);
        boolean hasPermission(String permission);
        default boolean isPlayer() {
            return false;
        }
    }

    /**
     * Interface for commands that can be executed.
     */
    public interface Command {
        void execute(CommandSource source, String[] args);
        
        default List<String> suggest(CommandSource source, String[] currentArgs) {
            return List.of();
        }
        
        default boolean hasPermission(CommandSource source) {
            return true;
        }
    }

    /**
     * Registers a command with the specified alias.
     */
    public void registerCommand(String alias, Command command) {
        Preconditions.checkNotNull(alias, "alias");
        Preconditions.checkNotNull(command, "command");
        
        if (commands.containsKey(alias)) {
            logger.warn("Command '{}' is already registered, overriding...", alias);
        }
        
        commands.put(alias.toLowerCase(), command);
        logger.info("Registered command: {}", alias);
    }

    /**
     * Unregisters a command.
     */
    public Optional<Command> unregisterCommand(String alias) {
        Preconditions.checkNotNull(alias, "alias");
        Command removed = commands.remove(alias.toLowerCase());
        if (removed != null) {
            logger.info("Unregistered command: {}", alias);
        }
        return Optional.ofNullable(removed);
    }

    /**
     * Executes a command for the specified source.
     */
    public boolean executeCommand(CommandSource source, String cmdLine) {
        Preconditions.checkNotNull(source, "source");
        Preconditions.checkNotNull(cmdLine, "cmdLine");

        String[] split = cmdLine.split(" ", 2);
        String alias = split[0].toLowerCase();
        String args = split.length > 1 ? split[1] : "";

        Optional<Command> command = getCommand(alias);
        if (command.isEmpty()) {
            source.sendMessage(Component.text("Unknown command.", NamedTextColor.RED));
            return false;
        }

        if (!command.get().hasPermission(source)) {
            source.sendMessage(Component.text("You do not have permission to use this command.", 
                NamedTextColor.RED));
            return false;
        }

        try {
            command.get().execute(source, args.split(" "));
            return true;
        } catch (Exception e) {
            logger.error("Error executing command '{}' for {}", alias, source, e);
            source.sendMessage(Component.text("An error occurred while executing this command.", 
                NamedTextColor.RED));
            return false;
        }
    }

    /**
     * Gets a registered command.
     */
    public Optional<Command> getCommand(String alias) {
        Preconditions.checkNotNull(alias, "alias");
        return Optional.ofNullable(commands.get(alias.toLowerCase()));
    }

    /**
     * Gets suggestions for command completion.
     */
    public List<String> suggest(CommandSource source, String cmdLine) {
        Preconditions.checkNotNull(source, "source");
        Preconditions.checkNotNull(cmdLine, "cmdLine");

        String[] split = cmdLine.split(" ", -1);
        String alias = split[0].toLowerCase();

        Optional<Command> command = getCommand(alias);
        if (command.isEmpty()) {
            return commands.keySet().stream()
                .filter(cmd -> cmd.startsWith(alias))
                .filter(cmd -> {
                    Command cmd2 = commands.get(cmd);
                    return cmd2 != null && cmd2.hasPermission(source);
                })
                .toList();
        }

        if (!command.get().hasPermission(source)) {
            return List.of();
        }

        String[] args = new String[split.length - 1];
        System.arraycopy(split, 1, args, 0, args.length);
        return command.get().suggest(source, args);
    }
}