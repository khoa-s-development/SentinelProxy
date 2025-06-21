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
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

public class UpdateChecker {
    private static final Logger logger = LoggerFactory.getLogger(UpdateChecker.class);
    private static final String GITHUB_API_URL = "https://api.github.com/repos/Khoasoma/SentinelProxy/releases/latest";
    private static final String USER_AGENT = "SentinelProxy-UpdateChecker/1.0";
    
    private final Velocity velocity;
    private final HttpClient httpClient;
    private final Gson gson;
    private String currentVersion;
    private String latestVersion;
    private String downloadUrl;

    public UpdateChecker(Velocity velocity) {
        this.velocity = velocity;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
        this.gson = new Gson();
        this.currentVersion = velocity.getServer().getVersion().getVersion();
    }

    public CompletableFuture<Boolean> checkForUpdates() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(GITHUB_API_URL))
                    .header("User-Agent", USER_AGENT)
                    .header("Accept", "application/vnd.github.v3+json")
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();

                HttpResponse<String> response = httpClient.send(request, 
                    HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 200) {
                    return parseResponse(response.body());
                } else {
                    logger.warn("Failed to check for updates: HTTP {}", response.statusCode());
                    return false;
                }
            } catch (IOException | InterruptedException e) {
                logger.error("Error checking for updates", e);
                Thread.currentThread().interrupt();
                return false;
            }
        }).exceptionally(throwable -> {
            logger.error("Exception during update check", throwable);
            return false;
        });
    }

    private boolean parseResponse(String responseBody) {
        try {
            JsonObject release = gson.fromJson(responseBody, JsonObject.class);
            latestVersion = release.get("tag_name").getAsString();
            
            // Remove 'v' prefix if present
            String cleanLatestVersion = latestVersion.startsWith("v") ? 
                latestVersion.substring(1) : latestVersion;
            String cleanCurrentVersion = currentVersion.startsWith("v") ? 
                currentVersion.substring(1) : currentVersion;

            // Get download URL
            if (release.has("assets") && release.get("assets").getAsJsonArray().size() > 0) {
                downloadUrl = release.get("assets").getAsJsonArray()
                    .get(0).getAsJsonObject()
                    .get("browser_download_url").getAsString();
            } else {
                downloadUrl = release.get("html_url").getAsString();
            }

            boolean updateAvailable = isNewerVersion(cleanCurrentVersion, cleanLatestVersion);
            
            if (updateAvailable) {
                logger.info("Update available: {} -> {}", currentVersion, latestVersion);
                logger.info("Download URL: {}", downloadUrl);
            } else {
                logger.debug("No updates available. Current: {}, Latest: {}", 
                    currentVersion, latestVersion);
            }
            
            return updateAvailable;
        } catch (Exception e) {
            logger.error("Error parsing update response", e);
            return false;
        }
    }

    private boolean isNewerVersion(String current, String latest) {
        try {
            // Simple version comparison (works for semantic versioning)
            String[] currentParts = current.replace("-SNAPSHOT", "").split("\\.");
            String[] latestParts = latest.replace("-SNAPSHOT", "").split("\\.");
            
            int maxLength = Math.max(currentParts.length, latestParts.length);
            
            for (int i = 0; i < maxLength; i++) {
                int currentPart = i < currentParts.length ? 
                    Integer.parseInt(currentParts[i]) : 0;
                int latestPart = i < latestParts.length ? 
                    Integer.parseInt(latestParts[i]) : 0;
                
                if (latestPart > currentPart) {
                    return true;
                } else if (latestPart < currentPart) {
                    return false;
                }
            }
            return false;
        } catch (NumberFormatException e) {
            logger.warn("Could not parse version numbers for comparison: {} vs {}", 
                current, latest);
            return false;
        }
    }

    public String getCurrentVersion() {
        return currentVersion;
    }

    public String getLatestVersion() {
        return latestVersion;
    }

    public String getDownloadUrl() {
        return downloadUrl;
    }

    public void setCurrentVersion(String currentVersion) {
        this.currentVersion = currentVersion;
    }
}