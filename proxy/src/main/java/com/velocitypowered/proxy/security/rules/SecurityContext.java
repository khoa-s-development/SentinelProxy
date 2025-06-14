/*
 * Copyright (C) 2018-2023 Velocity Contributors
 * Current Date and Time (UTC): 2025-06-13 18:23:41
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security.rules;

import java.net.InetAddress;
import java.time.Instant;

public abstract class SecurityContext {
    protected final Instant timestamp;
    protected String reason;

    protected SecurityContext() {
        this.timestamp = Instant.now();
    }

    public abstract InetAddress getAddress();
    
    public Instant getTimestamp() {
        return timestamp;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }
}