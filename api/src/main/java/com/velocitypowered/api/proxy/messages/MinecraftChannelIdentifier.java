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

package com.velocitypowered.api.proxy.messages;

import static com.google.common.base.Preconditions.checkArgument;

import com.google.common.base.Strings;
import java.util.Objects;
import net.kyori.adventure.key.Key;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Represents a Minecraft 1.13+ channel identifier. This class is immutable and safe for
 * multi-threaded use.
 */
public final class MinecraftChannelIdentifier implements ChannelIdentifier {

  private final String namespace;
  private final String name;

  private MinecraftChannelIdentifier(String namespace, String name) {
    this.namespace = namespace;
    this.name = name;
  }

  /**
   * Creates an identifier in the default namespace ({@code minecraft}). Plugins are strongly
   * encouraged to provide their own namespace.
   *
   * @param name the name in the default namespace to use
   * @return a new channel identifier
   */
  public static MinecraftChannelIdentifier forDefaultNamespace(String name) {
    return new MinecraftChannelIdentifier(Key.MINECRAFT_NAMESPACE, name);
  }

  /**
   * Creates an identifier in the specified namespace.
   *
   * @param namespace the namespace to use
   * @param name the channel name inside the specified namespace
   * @return a new channel identifier
   */
  public static MinecraftChannelIdentifier create(String namespace, String name) {
    checkArgument(!Strings.isNullOrEmpty(namespace), "namespace is null or empty");
    checkArgument(name != null, "namespace is null or empty");
    checkArgument(Key.parseableNamespace(namespace),
        "namespace is not valid, must match: [a-z0-9_.-] got %s", namespace);
    checkArgument(Key.parseableValue(name),
        "name is not valid, must match: [a-z0-9/._-] got %s", name);
    return new MinecraftChannelIdentifier(namespace, name);
  }

  /**
   * Creates an channel identifier from the specified Minecraft identifier.
   *
   * @param identifier the Minecraft identifier
   * @return a new channel identifier
   */
  public static MinecraftChannelIdentifier from(String identifier) {
    int colonPos = identifier.indexOf(':');
    if (colonPos == -1) {
      return create(Key.MINECRAFT_NAMESPACE, identifier);
    } else if (colonPos == 0) {
      return create(Key.MINECRAFT_NAMESPACE, identifier.substring(1));
    }
    String namespace = identifier.substring(0, colonPos);
    String name = identifier.substring(colonPos + 1);
    return create(namespace, name);
  }

  /**
   * Creates an channel identifier from the specified Minecraft identifier.
   *
   * @param key the Minecraft key to use
   * @return a new channel identifier
   */
  public static MinecraftChannelIdentifier from(Key key) {
    return create(key.namespace(), key.value());
  }

  public String getNamespace() {
    return namespace;
  }

  public String getName() {
    return name;
  }

  public Key asKey() {
    return Key.key(namespace, name);
  }

  @Override
  public String toString() {
    return namespace + ":" + name + " (modern)";
  }

  @Override
  public boolean equals(@Nullable Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    MinecraftChannelIdentifier that = (MinecraftChannelIdentifier) o;
    return Objects.equals(namespace, that.namespace)
        && Objects.equals(name, that.name);
  }

  @Override
  public int hashCode() {
    return Objects.hash(namespace, name);
  }

  @Override
  public String getId() {
    return namespace + ":" + name;
  }
}
