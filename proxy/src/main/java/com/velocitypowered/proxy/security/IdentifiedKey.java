/*
 * Copyright (C) 2018-2023 Velocity Contributors
 *
 * Current Date and Time (UTC - YYYY-MM-DD HH:MM:SS formatted): 2025-06-15 13:41:13
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security;

import com.google.common.base.Preconditions;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import org.checkerframework.checker.nullness.qual.Nullable;

public class IdentifiedKey {
    private final byte[] signature;
    private final PublicKey publicKey;
    private final Instant expiresAt;
    private final boolean hasSignature;

    public IdentifiedKey(byte[] signature, PublicKey publicKey, Instant expiresAt) {
        this.signature = Preconditions.checkNotNull(signature, "signature");
        this.publicKey = Preconditions.checkNotNull(publicKey, "publicKey");
        this.expiresAt = Preconditions.checkNotNull(expiresAt, "expiresAt");
        this.hasSignature = signature.length > 0;
    }

    public byte[] getSignature() {
        return Arrays.copyOf(signature, signature.length);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean hasSignature() {
        return hasSignature;
    }

    /**
     * Checks if the key is currently valid.
     *
     * @return true if the key has not expired, false otherwise
     */
    public boolean isValid() {
        return !isExpired();
    }

    /**
     * Checks if the key has expired.
     *
     * @return true if the key has expired, false otherwise
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        
        IdentifiedKey that = (IdentifiedKey) o;
        return hasSignature == that.hasSignature &&
               Arrays.equals(signature, that.signature) &&
               Objects.equals(publicKey, that.publicKey) &&
               Objects.equals(expiresAt, that.expiresAt);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(publicKey, expiresAt, hasSignature);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }

    @Override 
    public String toString() {
        return String.format(
            "IdentifiedKey(signature=%s, publicKey=%s, expiresAt=%s, hasSignature=%s)",
            Arrays.toString(signature),
            publicKey,
            expiresAt,
            hasSignature
        );
    }

    /**
     * Creates a builder for IdentifiedKey.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder class for IdentifiedKey.
     */
    public static class Builder {
        private byte[] signature;
        private PublicKey publicKey;
        private Instant expiresAt;

        private Builder() {}

        public Builder signature(byte[] signature) {
            this.signature = signature;
            return this;
        }

        public Builder publicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public Builder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public IdentifiedKey build() {
            return new IdentifiedKey(
                signature != null ? signature : new byte[0],
                publicKey,
                expiresAt
            );
        }
    }
}