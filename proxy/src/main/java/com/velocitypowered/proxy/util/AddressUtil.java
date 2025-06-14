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

package com.velocitypowered.proxy.util;

import com.google.common.base.Preconditions;
import com.velocitypowered.api.network.ProtocolVersion;
import io.netty.channel.unix.DomainSocketAddress;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

/**
 * Network address utilities for Velocity.
 * Last Updated: 2025-06-13 18:14:41 UTC
 * Current User: Khoasoma
 */
public final class AddressUtil {
    private static final Logger logger = LogManager.getLogger(AddressUtil.class);
    private static final Pattern VALID_IPV4_PATTERN = Pattern.compile(
            "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
            + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");
    private static final Pattern VALID_IPV6_PATTERN = Pattern.compile(
            "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");
    private static final Pattern VALID_HOSTNAME_PATTERN = Pattern.compile(
            "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*"
            + "([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$");

    private AddressUtil() {
        throw new AssertionError();
    }

    /**
     * Parses an address in the format hostname:port.
     *
     * @param address the address to parse
     * @return the parsed address
     */
    public static @NonNull InetSocketAddress parseAddress(@NonNull String address) {
        Preconditions.checkNotNull(address, "address");
        URI uri;

        try {
            uri = new URI("tcp://" + address);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid address " + address, e);
        }

        String host = uri.getHost();
        int port = uri.getPort();

        checkPort(port);
        if (host == null) {
            throw new IllegalArgumentException("Invalid hostname/IP " + address);
        }

        return InetSocketAddress.createUnresolved(host, port);
    }

    /**
     * Parses an address in the format hostname:port with a specified port if none is present.
     *
     * @param address the address to parse
     * @param defaultPort the default port to use if none is specified
     * @return the parsed address
     */
    public static @NonNull InetSocketAddress parseAddress(@NonNull String address, int defaultPort) {
        Preconditions.checkNotNull(address, "address");
        try {
            URI uri = new URI("tcp://" + address);
            String host = uri.getHost();
            int port = uri.getPort();
            if (port == -1) {
                port = defaultPort;
            }

            checkPort(port);
            if (host == null) {
                throw new IllegalArgumentException("Invalid hostname/IP " + address);
            }

            return InetSocketAddress.createUnresolved(host, port);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid address " + address, e);
        }
    }

    /**
     * Validates that the port is valid.
     *
     * @param port the port to check
     */
    private static void checkPort(int port) {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Port " + port + " is out of range");
        }
    }

    /**
     * Gets the address represented by the given {@link InetSocketAddress} as a string.
     *
     * @param addr the address to convert
     * @return the address in string form
     */
    public static @NonNull String toString(@NonNull InetSocketAddress addr) {
        Preconditions.checkNotNull(addr, "addr");
        return addr.getHostString() + ":" + addr.getPort();
    }

    /**
     * Checks if the specified address is a valid IPv4 address.
     *
     * @param address the address to check
     * @return true if valid IPv4, false otherwise 
     */
    public static boolean isValidIPv4(@NonNull String address) {
        return address != null && VALID_IPV4_PATTERN.matcher(address).matches();
    }

    /**
     * Checks if the specified address is a valid IPv6 address.
     *
     * @param address the address to check  
     * @return true if valid IPv6, false otherwise
     */
    public static boolean isValidIPv6(@NonNull String address) {
        return address != null && VALID_IPV6_PATTERN.matcher(address).matches();
    }

    /**
     * Checks if the specified string is a valid hostname.
     *
     * @param hostname the hostname to check
     * @return true if valid hostname, false otherwise
     */
    public static boolean isValidHostname(@NonNull String hostname) {
        return hostname != null && VALID_HOSTNAME_PATTERN.matcher(hostname).matches();
    }

    /**
     * Gets a standardized form of the specified address.
     * 
     * @param addr the address to standardize
     * @return the standardized address
     */
    public static @NonNull String standardizeAddress(@NonNull String addr) {
        Preconditions.checkNotNull(addr, "addr");
        
        if (addr.startsWith("[") && addr.endsWith("]")) {
            // IPv6 address
            return addr.substring(1, addr.length() - 1);
        }
        return addr.toLowerCase();
    }

    /**
     * Gets the numerical value of an IP address.
     *
     * @param addr the address to convert
     * @return the numerical value
     */
    public static long ipToLong(@NonNull InetAddress addr) {
        Preconditions.checkNotNull(addr, "addr");
        byte[] bytes = addr.getAddress();
        long result = 0;
        for (byte b : bytes) {
            result = result << 8 | (b & 0xFF);
        }
        return result;
    }

    /**
     * Checks if an address/port combination is valid for a specific protocol version.
     *
     * @param address the address to check
     * @param port the port to check  
     * @param protocolVersion the protocol version
     * @return true if valid, false otherwise
     */
    public static boolean isValidAddressAndPortForVersion(@NonNull String address, int port, 
            @NonNull ProtocolVersion protocolVersion) {
        Preconditions.checkNotNull(address, "address");
        Preconditions.checkNotNull(protocolVersion, "protocolVersion");

        if (port < 1 || port > 65535) {
            return false;
        }

        // Check address format based on protocol version
        if (protocolVersion.compareTo(ProtocolVersion.MINECRAFT_1_16) >= 0) {
            return isValidIPv4(address) || isValidIPv6(address) || isValidHostname(address);
        } else {
            return isValidIPv4(address) || isValidHostname(address);
        }
    }

    /**
     * Creates a socket address for a Unix domain socket.
     *
     * @param path the path to the socket
     * @return the socket address
     */
    public static @NonNull DomainSocketAddress createUnixDomainSocketAddress(@NonNull String path) {
        Preconditions.checkNotNull(path, "path");
        return new DomainSocketAddress(path);
    }

    /**
     * Checks if an address is a loopback address.
     *
     * @param addr the address to check
     * @return true if loopback, false otherwise
     */
    public static boolean isLoopbackAddress(@NonNull InetAddress addr) {
        Preconditions.checkNotNull(addr, "addr");
        return addr.isLoopbackAddress();
    }

    /**
     * Logs details about an address for debugging purposes.
     *
     * @param addr the address to log
     * @param context additional context
     */
    public static void logAddressDetails(@NonNull InetSocketAddress addr, String context) {
        if (logger.isDebugEnabled()) {
            logger.debug("{}: Address: {}, Hostname: {}, Port: {}, Resolved: {}", 
                context,
                addr.getAddress(),
                addr.getHostName(),
                addr.getPort(),
                !addr.isUnresolved());
        }
    }
}