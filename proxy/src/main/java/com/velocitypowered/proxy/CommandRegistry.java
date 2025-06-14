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
 * Current Date and Time (UTC - YYYY-MM-DD HH:MM:SS formatted): 2025-06-14 11:48:00
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import com.velocitypowered.api.command.Command;
import com.velocitypowered.api.command.CommandSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;

public class CommandRegistry {
    private static final Logger logger = LoggerFactory.getLogger(CommandRegistry.class);
    private final Velocity velocity;
    private final Map<String, Command> commands;
    private final Map<String, String> aliases;
    
    public CommandRegistry(Velocity velocity) {
        this.velocity = velocity;
        this.commands = Maps.newHashMap();
        this.aliases = Maps.newHashMap();
    }

    public void registerCommand(String name, Command command) {
        commands.put(name.toLowerCase(), command);
        velocity.getServer().getCommandManager().register(name, command);
        logger.debug("Registered command: {}", name);
    }

    public void registerAlias(String alias, String command) {
        alias = alias.toLowerCase();
        command = command.toLowerCase();
        
        if (!commands.containsKey(command)) {
            logger.warn("Cannot create alias {} for non-existent command {}", alias, command);
            return;
        }

        aliases.put(alias, command);
        velocity.getServer().getCommandManager().register(alias, commands.get(command));
        logger.debug("Registered command alias: {} -> {}", alias, command);
    }

    public Optional<Command> getCommand(String name) {
        name = name.toLowerCase();
        Command command = commands.get(name);
        if (command == null) {
            String aliasTarget = aliases.get(name);
            if (aliasTarget != null) {
                command = commands.get(aliasTarget);
            }
        }
        return Optional.ofNullable(command);
    }

    public boolean executeCommand(CommandSource source, String commandLine) {
        String[] parts = commandLine.split(" ", 2);
        String name = parts[0].toLowerCase();
        String args = parts.length > 1 ? parts[1] : "";

        Optional<Command> command = getCommand(name);
        if (!command.isPresent()) {
            return false;
        }

        try {
            command.get().execute(source, args.split(" "));
            return true;
        } catch (Exception e) {
            logger.error("Error executing command: {}", name, e);
            return false;
        }
    }

    public void unregisterCommand(String name) {
        name = name.toLowerCase();
        commands.remove(name);
        velocity.getServer().getCommandManager().unregister(name);
        
        // Remove any aliases pointing to this command
        aliases.entrySet().removeIf(entry -> entry.getValue().equals(name));
        logger.debug("Unregistered command: {}", name);
    }

    public ImmutableList<String> getRegisteredCommands() {
        return ImmutableList.copyOf(commands.keySet());
    }

    public ImmutableList<String> getCommandAliases() {
        return ImmutableList.copyOf(aliases.keySet());
    }

    public void clearCommands() {
        commands.keySet().forEach(name -> 
            velocity.getServer().getCommandManager().unregister(name));
        commands.clear();
        aliases.clear();
        logger.info("Cleared all registered commands");
    }
}