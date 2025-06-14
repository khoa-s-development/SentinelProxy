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
 */

package com.velocitypowered.proxy.protection.ratelimit;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class RateLimiter<K> {
    private final LoadingCache<K, TokenBucket> buckets;
    private final int maxTokens;
    private final long refillInterval;

    public RateLimiter(int maxTokens, long refillInterval, TimeUnit timeUnit) {
        this.maxTokens = maxTokens;
        this.refillInterval = timeUnit.toMillis(refillInterval);
        
        this.buckets = CacheBuilder.newBuilder()
            .expireAfterAccess(1, TimeUnit.HOURS)
            .build(new CacheLoader<K, TokenBucket>() {
                @Override
                public TokenBucket load(K key) {
                    return new TokenBucket(maxTokens, System.currentTimeMillis());
                }
            });
    }

    public boolean tryAcquire(K key) {
        return tryAcquire(key, 1);
    }

    public boolean tryAcquire(K key, int tokens) {
        TokenBucket bucket = buckets.getUnchecked(key);
        synchronized (bucket) {
            bucket.refill();
            if (bucket.getTokens() >= tokens) {
                bucket.consume(tokens);
                return true;
            }
            return false;
        }
    }

    private class TokenBucket {
        private final AtomicInteger tokens;
        private long lastRefillTime;

        TokenBucket(int tokens, long lastRefillTime) {
            this.tokens = new AtomicInteger(tokens);
            this.lastRefillTime = lastRefillTime;
        }

        void refill() {
            long now = System.currentTimeMillis();
            long timePassed = now - lastRefillTime;
            
            if (timePassed >= refillInterval) {
                long refillAmount = timePassed / refillInterval;
                int newTokens = Math.min(
                    maxTokens,
                    tokens.get() + (int) refillAmount
                );
                tokens.set(newTokens);
                lastRefillTime = now;
            }
        }

        void consume(int amount) {
            tokens.addAndGet(-amount);
        }

        int getTokens() {
            return tokens.get();
        }
    }
}