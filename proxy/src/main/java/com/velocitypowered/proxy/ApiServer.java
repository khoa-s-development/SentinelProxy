/*
 * Copyright (C) 2018-2023 Velocity Contributors
 */

package com.velocitypowered.proxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple API server implementation.
 */
public class ApiServer {
    private static final Logger logger = LoggerFactory.getLogger(ApiServer.class);
    private boolean running = false;
    
    public void start() {
        if (!running) {
            running = true;
            logger.info("API Server started");
        }
    }
    
    public void stop() {
        if (running) {
            running = false;
            logger.info("API Server stopped");
        }
    }
    
    public boolean isRunning() {
        return running;
    }
}