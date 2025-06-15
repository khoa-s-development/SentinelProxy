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
 * Current Date and Time (UTC): 2025-06-14 08:27:36
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.ml;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.velocitypowered.proxy.protocol.packet.PacketWrapper;
import io.netty.channel.ChannelHandlerContext;
import okhttp3.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import com.google.common.cache.Cache; 
import com.google.common.cache.CacheBuilder;
import java.util.concurrent.TimeUnit;

public class AIAnalyzer {
    private static final Logger logger = LogManager.getLogger(AIAnalyzer.class);

    // Core components 
    private final String apiEndpoint;
    private final OkHttpClient httpClient;
    private final Gson gson;
    private final ExecutorService analysisExecutor;
    private final ScheduledExecutorService maintenanceExecutor;

    // ML model data
    private final Map<String, FeatureExtractor> featureExtractors;
    private final Map<String, PatternProfile> patternProfiles;
    private final BlockingQueue<TrainingSample> trainingQueue;
    private final Cache<String, PredictionResult> predictionCache;

    // Configuration
    private final int maxQueueSize = 10000;
    private final int maxCacheSize = 5000;
    private final Duration cacheExpiry = Duration.ofMinutes(5);
    private final int batchSize = 100;
    private final double defaultThreshold = 0.8;

    // Performance metrics
    private final AtomicInteger totalPredictions = new AtomicInteger();
    private final AtomicInteger totalTrainingSamples = new AtomicInteger();

    public AIAnalyzer(String apiEndpoint) {
        this.apiEndpoint = apiEndpoint;
        this.gson = new Gson();

        // Initialize HTTP client
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .writeTimeout(5, TimeUnit.SECONDS)
            .connectionPool(new ConnectionPool(5, 1, TimeUnit.MINUTES))
            .build();

        // Initialize executors
        this.analysisExecutor = new ThreadPoolExecutor(
            2,
            4,
            60L,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(),
            new ThreadFactoryBuilder()
                .setNameFormat("ai-analysis-%d")
                .setDaemon(true)
                .build()
        );

        this.maintenanceExecutor = Executors.newScheduledThreadPool(
            1,
            new ThreadFactoryBuilder()
                .setNameFormat("ai-maintenance")
                .setDaemon(true)
                .build()
        );

        // Initialize collections
        this.featureExtractors = new ConcurrentHashMap<>();
        this.patternProfiles = new ConcurrentHashMap<>();
        this.trainingQueue = new LinkedBlockingQueue<>(maxQueueSize);
        this.predictionCache = CacheBuilder.newBuilder()
            .maximumSize(maxCacheSize)
            .expireAfterWrite(cacheExpiry)
            .build();

        // Initialize feature extractors
        initializeFeatureExtractors();

        // Start maintenance tasks
        startMaintenanceTasks();
    }

    private void initializeFeatureExtractors() {
        featureExtractors.put("packet_size", new PacketSizeExtractor());
        featureExtractors.put("packet_rate", new PacketRateExtractor());
        featureExtractors.put("protocol_type", new ProtocolTypeExtractor());
        featureExtractors.put("connection_state", new ConnectionStateExtractor());
        featureExtractors.put("payload_pattern", new PayloadPatternExtractor());
    }

    public CompletableFuture<PredictionResult> analyzePacket(ChannelHandlerContext ctx, PacketWrapper packet) {
        return CompletableFuture.supplyAsync(() -> {
            String cacheKey = generateCacheKey(ctx, packet);
            
            try {
                // Check cache first
                PredictionResult cachedResult = predictionCache.getIfPresent(cacheKey);
                if (cachedResult != null) {
                    return cachedResult;
                }

                // Extract features
                Map<String, Object> features = extractFeatures(ctx, packet);

                // Get prediction from API
                PredictionResult result = getPrediction(features);
                
                // Update cache and metrics
                predictionCache.put(cacheKey, result);
                totalPredictions.incrementAndGet();

                // Queue for training if confidence is high
                if (Math.abs(result.confidence - 0.5) > 0.4) {
                    queueForTraining(features, result.malicious);
                }

                return result;

            } catch (Exception e) {
                logger.error("Error analyzing packet", e);
                return new PredictionResult(false, 0.0, "Analysis error");
            }
        }, analysisExecutor);
    }

    private String generateCacheKey(ChannelHandlerContext ctx, PacketWrapper packet) {
        InetSocketAddress address = (InetSocketAddress) ctx.channel().remoteAddress();
        return String.format("%s:%s:%d",
            address.getAddress().getHostAddress(),
            packet.getClass().getSimpleName(),
            System.currentTimeMillis() / 1000
        );
    }

    private Map<String, Object> extractFeatures(ChannelHandlerContext ctx, PacketWrapper packet) {
        Map<String, Object> features = new HashMap<>();
        
        for (Map.Entry<String, FeatureExtractor> entry : featureExtractors.entrySet()) {
            try {
                Object feature = entry.getValue().extract(ctx, packet);
                features.put(entry.getKey(), feature);
            } catch (Exception e) {
                logger.warn("Error extracting feature: " + entry.getKey(), e);
            }
        }

        return features;
    }

    private PredictionResult getPrediction(Map<String, Object> features) throws IOException {
        String jsonFeatures = gson.toJson(features);

        Request request = new Request.Builder()
            .url(apiEndpoint + "/predict")
            .post(RequestBody.create(jsonFeatures, MediaType.parse("application/json")))
            .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("API error: " + response.code());
            }

            Type type = new TypeToken<Map<String, Object>>(){}.getType();
            Map<String, Object> result = gson.fromJson(response.body().string(), type);

            return new PredictionResult(
                (boolean) result.get("malicious"),
                (double) result.get("confidence"),
                (String) result.get("reason")
            );
        }
    }

    private void queueForTraining(Map<String, Object> features, boolean isMalicious) {
        TrainingSample sample = new TrainingSample(features, isMalicious);
        if (!trainingQueue.offer(sample)) {
            logger.warn("Training queue full, dropping sample");
        } else {
            totalTrainingSamples.incrementAndGet();
        }
    }

    private void startMaintenanceTasks() {
        // Send training data periodically
        maintenanceExecutor.scheduleAtFixedRate(() -> {
            try {
                sendTrainingBatch();
            } catch (Exception e) {
                logger.error("Error sending training batch", e);
            }
        }, 5, 5, TimeUnit.MINUTES);

        // Clean up profiles periodically
        maintenanceExecutor.scheduleAtFixedRate(() -> {
            try {
                cleanupProfiles();
            } catch (Exception e) {
                logger.error("Error cleaning up profiles", e);
            }
        }, 1, 1, TimeUnit.HOURS);
    }

    private void sendTrainingBatch() throws IOException {
        List<TrainingSample> batch = new ArrayList<>();
        trainingQueue.drainTo(batch, batchSize);

        if (batch.isEmpty()) {
            return;
        }

        String jsonBatch = gson.toJson(batch);

        Request request = new Request.Builder()
            .url(apiEndpoint + "/train")
            .post(RequestBody.create(jsonBatch, MediaType.parse("application/json")))
            .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Training API error: " + response.code());
            }
            logger.info("Successfully sent {} training samples", batch.size());
        }
    }

    private void cleanupProfiles() {
        long cutoff = System.currentTimeMillis() - Duration.ofHours(1).toMillis();
        patternProfiles.entrySet().removeIf(entry -> 
            entry.getValue().getLastUpdate() < cutoff);
    }

    // Feature extractors
    private interface FeatureExtractor {
        Object extract(ChannelHandlerContext ctx, PacketWrapper packet);
    }

    private static class PacketSizeExtractor implements FeatureExtractor {
        @Override
        public Object extract(ChannelHandlerContext ctx, PacketWrapper packet) {
            return packet.getSize();
        }
    }

    private static class PacketRateExtractor implements FeatureExtractor {
        @Override
        public Object extract(ChannelHandlerContext ctx, PacketWrapper packet) {
            // Implementation to calculate packet rate
            return 0.0;
        }
    }

    private static class ProtocolTypeExtractor implements FeatureExtractor {
        @Override
        public Object extract(ChannelHandlerContext ctx, PacketWrapper packet) {
            return packet.getClass().getSimpleName();
        }
    }

    private static class ConnectionStateExtractor implements FeatureExtractor {
        @Override
        public Object extract(ChannelHandlerContext ctx, PacketWrapper packet) {
            return ctx.channel().isActive() ? "active" : "inactive";
        }
    }

    private static class PayloadPatternExtractor implements FeatureExtractor {
        @Override
        public Object extract(ChannelHandlerContext ctx, PacketWrapper packet) {
            // Implementation to analyze payload patterns
            return Collections.emptyMap();
        }
    }

    // Data classes
    private static class TrainingSample {
        private final Map<String, Object> features;
        private final boolean label;
        private final long timestamp;

        public TrainingSample(Map<String, Object> features, boolean label) {
            this.features = features;
            this.label = label;
            this.timestamp = System.currentTimeMillis();
        }
    }

    public static class PredictionResult {
        private final boolean malicious;
        private final double confidence;
        private final String reason;

        public PredictionResult(boolean malicious, double confidence, String reason) {
            this.malicious = malicious;
            this.confidence = confidence;
            this.reason = reason;
        }

        public boolean isMalicious() {
            return malicious;
        }

        public double getConfidence() {
            return confidence;
        }

        public String getReason() {
            return reason;
        }
    }

    private static class PatternProfile {
        private final Map<String, Object> features;
        private volatile long lastUpdate;

        public PatternProfile() {
            this.features = new ConcurrentHashMap<>();
            this.lastUpdate = System.currentTimeMillis();
        }

        public void updateFeature(String key, Object value) {
            features.put(key, value);
            lastUpdate = System.currentTimeMillis();
        }

        public long getLastUpdate() {
            return lastUpdate;
        }
    }
}