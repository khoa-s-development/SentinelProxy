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

package com.velocitypowered.proxy.protocol.packet;

import io.netty.buffer.ByteBuf;
import java.util.Optional;

public class PacketWrapper {
    private final int id;
    private final ByteBuf content;
    private final Direction direction;

    public PacketWrapper(int id, ByteBuf content, Direction direction) {
        this.id = id;
        this.content = content;
        this.direction = direction;
    }

    public int getId() {
        return id;
    }

    public ByteBuf getContent() {
        return content;
    }

    public Direction getDirection() {
        return direction;
    }

    public int getSize() {
        return content.readableBytes();
    }

    public void release() {
        content.release();
    }

    @Override
    public String toString() {
        return String.format("PacketWrapper(id=0x%02X, direction=%s, size=%d)", 
            id, direction, getSize());
    }

    public enum Direction {
        SERVERBOUND,
        CLIENTBOUND;

        public static Optional<Direction> fromString(String name) {
            try {
                return Optional.of(valueOf(name.toUpperCase()));
            } catch (IllegalArgumentException e) {
                return Optional.empty();
            }
        }
    }
}