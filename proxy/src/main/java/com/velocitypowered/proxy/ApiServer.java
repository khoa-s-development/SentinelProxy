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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.Map;
import java.util.HashMap;

public class ApiServer {
    private static final Logger logger = LoggerFactory.getLogger(ApiServer.class);
    private final Velocity velocity;
    private final Gson gson;
    private HttpServer server;
    private boolean running = false;
    private int port = 8080; // Default port

    public ApiServer(Velocity velocity) {
        this.velocity = velocity;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
    }

    public void start() {
        try {
            server = HttpServer.create(new InetSocketAddress(port), 0);
            setupEndpoints();
            server.setExecutor(Executors.newFixedThreadPool(4));
            server.start();
            running = true;
            logger.info("API Server started on port {}", port);
        } catch (IOException e) {
            logger.error("Failed to start API server", e);
        }
    }

    public void stop() {
        if (server != null && running) {
            server.stop(5);
            running = false;
            logger.info("API Server stopped");
        }
    }

    private void setupEndpoints() {
        server.createContext("/api/status", new StatusHandler());
        server.createContext("/api/players", new PlayersHandler());
        server.createContext("/api/servers", new ServersHandler());
        server.createContext("/api/security", new SecurityHandler());
    }

    public boolean isRunning() {
        return running;
    }

    public void setPort(int port) {
        this.port = port;
    }

    private class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, Object> status = new HashMap<>();
                status.put("status", "running");
                status.put("version", velocity.getServer().getVersion().getVersion());
                status.put("players", velocity.getServer().getPlayerCount());
                status.put("servers", velocity.getServer().getAllServers().size());
                
                sendJsonResponse(exchange, status);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private class PlayersHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, Object> response = new HashMap<>();
                response.put("count", velocity.getServer().getPlayerCount());
                response.put("players", velocity.getServer().getAllPlayers().stream()
                    .map(player -> {
                        Map<String, Object> playerInfo = new HashMap<>();
                        playerInfo.put("name", player.getUsername());
                        playerInfo.put("uuid", player.getUniqueId().toString());
                        return playerInfo;
                    }).toList());
                
                sendJsonResponse(exchange, response);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private class ServersHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, Object> response = new HashMap<>();
                response.put("servers", velocity.getServer().getAllServers().stream()
                    .map(server -> {
                        Map<String, Object> serverInfo = new HashMap<>();
                        serverInfo.put("name", server.getServerInfo().getName());
                        serverInfo.put("address", server.getServerInfo().getAddress().toString());
                        serverInfo.put("players", server.getPlayersConnected().size());
                        return serverInfo;
                    }).toList());
                
                sendJsonResponse(exchange, response);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private class SecurityHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, Object> response = new HashMap<>();
                response.put("security_enabled", true);
                response.put("ddos_protection", true);
                response.put("antibot_enabled", true);
                
                sendJsonResponse(exchange, response);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private void sendJsonResponse(HttpExchange exchange, Object data) throws IOException {
        String response = gson.toJson(data);
        byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
        
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(200, responseBytes.length);
        
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}