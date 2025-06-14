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

package com.velocitypowered.proxy.protection.util;

import com.google.common.net.InetAddresses;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SecurityUtils {
    private static final Logger logger = LogManager.getLogger(SecurityUtils.class);
    
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{3,16}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");

    private SecurityUtils() {
        // Utility class
    }

    public static boolean isValidUsername(String username) {
        return username != null && USERNAME_PATTERN.matcher(username).matches();
    }

    public static boolean isValidEmail(String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }

    public static boolean isPrivateAddress(InetAddress address) {
        return address.isLoopbackAddress() || 
               address.isSiteLocalAddress() || 
               address.isLinkLocalAddress();
    }

    public static String calculateHmac(String data, byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
            mac.init(secretKey);
            return bytesToHex(mac.doFinal(data.getBytes()));
        } catch (Exception e) {
            logger.error("Error calculating HMAC", e);
            return null;
        }
    }

    public static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes());
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Error hashing password", e);
            return null;
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    public static boolean isValidIp(String ip) {
        try {
            return InetAddresses.isInetAddress(ip);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public static String maskIp(String ip) {
        if (ip == null) {
            return null;
        }
        String[] parts = ip.split("\\.");
        if (parts.length == 4) {
            return parts[0] + "." + parts[1] + ".*.*";
        }
        return ip;
    }

    public static boolean isRateLimited(int attempts, int maxAttempts, long timeWindow) {
        return attempts >= maxAttempts;
    }
}