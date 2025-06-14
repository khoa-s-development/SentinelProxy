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

import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Multimap;
import com.velocitypowered.api.event.Event;
import com.velocitypowered.api.event.EventHandler;
import com.velocitypowered.api.event.Subscribe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

public class EventRegistry {
    private static final Logger logger = LoggerFactory.getLogger(EventRegistry.class);
    private final Velocity velocity;
    private final Multimap<Class<? extends Event>, RegisteredHandler> handlers;
    private final Collection<Object> registeredListeners;
    
    public EventRegistry(Velocity velocity) {
        this.velocity = velocity;
        this.handlers = HashMultimap.create();
        this.registeredListeners = new CopyOnWriteArrayList<>();
    }

    public void registerHandler(Object listener) {
        if (registeredListeners.contains(listener)) {
            logger.warn("Listener {} is already registered", listener.getClass().getName());
            return;
        }

        int methodsFound = 0;
        for (Method method : listener.getClass().getDeclaredMethods()) {
            Subscribe subscribe = method.getAnnotation(Subscribe.class);
            if (subscribe == null) continue;

            if (method.getParameterCount() != 1) {
                logger.error("Method {} has @Subscribe but has {} parameters (should be 1)",
                    method.getName(), method.getParameterCount());
                continue;
            }

            Class<?> eventClass = method.getParameterTypes()[0];
            if (!Event.class.isAssignableFrom(eventClass)) {
                logger.error("Method {} has @Subscribe but parameter is not an Event", method.getName());
                continue;
            }

            registerHandler(listener, method, subscribe, (Class<? extends Event>) eventClass);
            methodsFound++;
        }

        if (methodsFound > 0) {
            registeredListeners.add(listener);
            logger.debug("Registered {} event handlers for {}", 
                methodsFound, listener.getClass().getName());
        }
    }

    private void registerHandler(Object listener, Method method, Subscribe subscribe, 
                               Class<? extends Event> eventClass) {
        method.setAccessible(true);
        RegisteredHandler handler = new RegisteredHandler(listener, method, subscribe.order());
        handlers.put(eventClass, handler);
    }

    public void unregisterHandler(Object listener) {
        if (!registeredListeners.remove(listener)) {
            return;
        }

        handlers.entries().removeIf(entry -> entry.getValue().listener == listener);
        logger.debug("Unregistered all handlers for {}", listener.getClass().getName());
    }

    public void fireEvent(Event event) {
        Collection<RegisteredHandler> eventHandlers = handlers.get(event.getClass());
        if (eventHandlers.isEmpty()) {
            return;
        }

        // Sort handlers by order
        ImmutableList<RegisteredHandler> sortedHandlers = ImmutableList.sortedCopyOf(
            (h1, h2) -> Integer.compare(h2.order, h1.order), eventHandlers);

        for (RegisteredHandler handler : sortedHandlers) {
            try {
                handler.method.invoke(handler.listener, event);
            } catch (Exception e) {
                logger.error("Error dispatching event {} to {}", 
                    event.getClass().getName(), handler.listener.getClass().getName(), e);
            }
        }
    }

    public void clearHandlers() {
        handlers.clear();
        registeredListeners.clear();
        logger.info("Cleared all event handlers");
    }

    private static class RegisteredHandler {
        final Object listener;
        final Method method;
        final int order;

        RegisteredHandler(Object listener, Method method, int order) {
            this.listener = listener;
            this.method = method;
            this.order = order;
        }
    }

    public ImmutableList<Class<? extends Event>> getRegisteredEventTypes() {
        return ImmutableList.copyOf(handlers.keySet());
    }

    public ImmutableList<Object> getRegisteredListeners() {
        return ImmutableList.copyOf(registeredListeners);
    }
}