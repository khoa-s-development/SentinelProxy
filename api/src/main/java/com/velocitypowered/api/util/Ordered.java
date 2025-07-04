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

import org.jspecify.annotations.NullMarked;

/**
 * Something that is ordered.
 *
 * @param <T> the type
 * @since 3.3.0
 */
@NullMarked
@SuppressWarnings("ComparableType") // allows us to be more flexible
public interface Ordered<T> extends Comparable<T> {
  /**
   * Checks if {@code this} is greater than {@code that}.
   *
   * @param that the other object
   * @return {@code true} if {@code this} is greater than {@code that}, {@code false} otherwise
   * @since 3.3.0
   */
  default boolean greaterThan(final T that) {
    return this.compareTo(that) > 0;
  }

  /**
   * Checks if {@code this} is greater than or equal to {@code that}.
   *
   * @param that the other object
   * @return {@code true} if {@code this} is greater than or
   *     equal to {@code that}, {@code false} otherwise
   * @since 3.3.0
   */
  default boolean noLessThan(final T that) {
    return this.compareTo(that) >= 0;
  }

  /**
   * Checks if {@code this} is less than {@code that}.
   *
   * @param that the other object
   * @return {@code true} if {@code this} is less than {@code that}, {@code false} otherwise
   * @since 3.3.0
   */
  default boolean lessThan(final T that) {
    return this.compareTo(that) < 0;
  }

  /**
   * Checks if {@code this} is less than or equal to {@code that}.
   *
   * @param that the other object
   * @return {@code true} if {@code this} is less than or
   *     equal to {@code that}, {@code false} otherwise
   * @since 3.3.0
   */
  default boolean noGreaterThan(final T that) {
    return this.compareTo(that) <= 0;
  }

  /**
   * Checks if {@code this} is equal to {@code that}.
   *
   * @param that the other object
   * @return {@code true} if {@code this} is equal to {@code that}, {@code false} otherwise
   * @since 3.3.0
   */
  default boolean noGreaterOrLessThan(final T that) {
    return this.compareTo(that) == 0;
  }
}
