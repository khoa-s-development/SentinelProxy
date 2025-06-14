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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentMap;

public class ComponentRegistry {
    private static final Logger logger = LoggerFactory.getLogger(ComponentRegistry.class);
    private final Velocity velocity;
    private final ConcurrentMap<String, Object> components;
    
    public ComponentRegistry(Velocity velocity) {
        this.velocity = velocity;
        this.components = Maps.newConcurrentMap();
    }

    public void initialize() {
        logger.info("Initializing component registry...");
        // Initialize core components
        registerCoreComponents();
        // Initialize plugin components
        registerPluginComponents();
        logger.info("Component registry initialized with {} components", components.size());
    }

    private void registerCoreComponents() {
        // Register essential components
        register("securityManager", velocity.getServer().getSecurityManager());
        register("connectionManager", velocity.getServer().getConnectionManager());
        register("eventManager", velocity.getServer().getEventManager());
    }

    private void registerPluginComponents() {
        velocity.getServer().getPluginManager().getPlugins().forEach(plugin -> {
            String pluginId = plugin.getDescription().getId();
            register("plugin:" + pluginId, plugin);
        });
    }

    public void register(String name, Object component) {
        if (components.putIfAbsent(name, component) != null) {
            logger.warn("Component {} already registered, skipping", name);
            return;
        }
        logger.debug("Registered component: {}", name);
    }

    @SuppressWarnings("unchecked")
    public <T> Optional<T> getComponent(String name, Class<T> type) {
        Object component = components.get(name);
        if (component != null && type.isInstance(component)) {
            return Optional.of((T) component);
        }
        return Optional.empty();
    }

    public void cleanup() {
        logger.info("Cleaning up component registry...");
        components.clear();
    }

    public ImmutableList<String> getRegisteredComponents() {
        return ImmutableList.copyOf(components.keySet());
    }

    public void saveData() {
        logger.info("Saving component data...");
        components.forEach((name, component) -> {
            try {
                if (component instanceof AutoCloseable) {
                    ((AutoCloseable) component).close();
                }
            } catch (Exception e) {
                logger.error("Error saving component data for: {}", name, e);
            }
        });
    }
}