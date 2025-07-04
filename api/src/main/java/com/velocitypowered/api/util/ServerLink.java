/*
 * Copyright (C) 2021-2024 Velocity Contributors
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

package com.velocitypowered.api.util;

import com.google.common.base.Preconditions;
import java.net.URI;
import java.util.Optional;
import net.kyori.adventure.text.Component;
import org.jetbrains.annotations.Nullable;

/**
 * Represents a custom URL servers can show in player pause menus.
 * Links can be of a built-in type or use a custom component text label.
 */
public final class ServerLink {

  private @Nullable Type type;
  private @Nullable Component label;
  private final URI url;

  private ServerLink(Component label, String url) {
    this.label = Preconditions.checkNotNull(label, "label");
    this.url = URI.create(url);
  }

  private ServerLink(Type type, String url) {
    this.type = Preconditions.checkNotNull(type, "type");
    this.url = URI.create(url);
  }

  /**
   * Construct a server link with a custom component label.
   *
   * @param label a custom component label to display
   * @param link  the URL to open when clicked
   */
  public static ServerLink serverLink(Component label, String link) {
    return new ServerLink(label, link);
  }

  /**
   * Construct a server link with a built-in type.
   *
   * @param type the {@link Type built-in type} of link
   * @param link the URL to open when clicked
   */
  public static ServerLink serverLink(Type type, String link) {
    return new ServerLink(type, link);
  }

  /**
   * Get the type of the server link.
   *
   * @return the type of the server link
   */
  public Optional<Type> getBuiltInType() {
    return Optional.ofNullable(type);
  }

  /**
   * Get the custom component label of the server link.
   *
   * @return the custom component label of the server link
   */
  public Optional<Component> getCustomLabel() {
    return Optional.ofNullable(label);
  }

  /**
   * Get the link {@link URI}.
   *
   * @return the link {@link URI}
   */
  public URI getUrl() {
    return url;
  }

  /**
   * Built-in types of server links.
   *
   * @apiNote {@link Type#BUG_REPORT} links are shown on the connection error screen
   */
  public enum Type {
    BUG_REPORT,
    COMMUNITY_GUIDELINES,
    SUPPORT,
    STATUS,
    FEEDBACK,
    COMMUNITY,
    WEBSITE,
    FORUMS,
    NEWS,
    ANNOUNCEMENTS
  }

}
