package com.velocitypowered.proxy.monitoring;

import io.prometheus.client.Counter;
import io.prometheus.client.Gauge;
import io.prometheus.client.Histogram;
import io.prometheus.client.hotspot.DefaultExports;
import com.velocitypowered.proxy.VelocityServer;

public class MonitoringManager {
    private final VelocityServer server;
    
    // Metrics for monitoring
    private final Counter connectionsTotal;
    private final Gauge activeConnections;
    private final Histogram latency;

    public MonitoringManager(VelocityServer server) {
        this.server = server;
        
        // Initialize Prometheus metrics
        this.connectionsTotal = Counter.build()
            .name("velocity_connections_total")
            .help("Total number of connections")
            .register();

        this.activeConnections = Gauge.build()
            .name("velocity_active_connections")
            .help("Number of currently active connections")
            .register();

        this.latency = Histogram.build()
            .name("velocity_latency_seconds")
            .help("Request latency in seconds")
            .register();

        // Enable JVM metrics
        DefaultExports.initialize();
    }

    public Counter getConnectionsTotal() {
        return connectionsTotal;
    }

    public Gauge getActiveConnections() {
        return activeConnections;
    }

    public Histogram getLatency() {
        return latency;
    }
}