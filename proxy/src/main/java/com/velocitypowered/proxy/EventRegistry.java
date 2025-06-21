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
 * Current Date and Time (UTC): 2025-06-21 12:05:58
 * Current User's Login: akk1to
 */

package com.velocitypowered.proxy;

import com.google.common.collect.Maps;
import com.velocitypowered.api.event.EventHandler;
import com.velocitypowered.api.event.EventManager;
import com.velocitypowered.api.event.Subscribe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;

public class EventRegistry {
    private static final Logger logger = LoggerFactory.getLogger(EventRegistry.class);
    private final Velocity velocity;
    private final ConcurrentMap<Class<?>, Set<RegisteredListener>> listeners;
    private final EventManager eventManager;
    
    public EventRegistry(Velocity velocity) {
        this.velocity = velocity;
        this.listeners = Maps.newConcurrentMap();
        this.eventManager = velocity.getServer().getEventManager();
    }

    public void initialize() {
        logger.info("Initializing event registry...");
        registerCoreEventHandlers();
        logger.info("Event registry initialized");
    }

    private void registerCoreEventHandlers() {
        // Register core event handlers here
        // This is where you would register handlers for security, monitoring, etc.
    }

    public <T> void registerListener(Object plugin, Class<T> eventClass, EventHandler<T> handler) {
        RegisteredListener listener = new RegisteredListener(plugin, handler);
        listeners.computeIfAbsent(eventClass, k -> new CopyOnWriteArraySet<>()).add(listener);
        logger.debug("Registered listener for event: {}", eventClass.getSimpleName());
    }

    public void registerListeners(Object plugin, Object listener) {
        Class<?> listenerClass = listener.getClass();
        Method[] methods = listenerClass.getDeclaredMethods();
        
        for (Method method : methods) {
            Subscribe subscribe = method.getAnnotation(Subscribe.class);
            if (subscribe != null && method.getParameterCount() == 1) {
                Class<?> eventClass = method.getParameterTypes()[0];
                try {
                    method.setAccessible(true);
                    EventHandler<Object> handler = event -> {
                        try {
                            method.invoke(listener, event);
                        } catch (Exception e) {
                            logger.error("Error invoking event handler", e);
                        }
                    };
                    registerListener(plugin, eventClass, handler);
                } catch (Exception e) {
                    logger.error("Failed to register event handler: {}", method.getName(), e);
                }
            }
        }
    }

    public void unregisterListeners(Object plugin) {
        listeners.values().forEach(listenerSet -> 
            listenerSet.removeIf(listener -> listener.plugin.equals(plugin))
        );
        logger.debug("Unregistered all listeners for plugin: {}", plugin.getClass().getSimpleName());
    }

    public void cleanup() {
        logger.info("Cleaning up event registry...");
        listeners.clear();
    }

    private static class RegisteredListener {
        private final Object plugin;
        private final EventHandler<?> handler;

        public RegisteredListener(Object plugin, EventHandler<?> handler) {
            this.plugin = plugin;
            this.handler = handler;
        }
    }
}