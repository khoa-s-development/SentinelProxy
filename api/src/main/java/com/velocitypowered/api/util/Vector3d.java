/*
 * Copyright (C) 2018-2025 Velocity Contributors
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

import java.util.Objects;

/**
 * Represents a three-dimensional vector with double precision.
 */
public final class Vector3d {

  /**
   * Zero vector.
   */
  public static final Vector3d ZERO = new Vector3d(0, 0, 0);

  private final double x;
  private final double y;
  private final double z;

  /**
   * Creates a new Vector3d.
   *
   * @param x the x coordinate
   * @param y the y coordinate
   * @param z the z coordinate
   */
  public Vector3d(double x, double y, double z) {
    this.x = x;
    this.y = y;
    this.z = z;
  }

  /**
   * Gets the x coordinate.
   *
   * @return the x coordinate
   */
  public double getX() {
    return x;
  }

  /**
   * Gets the y coordinate.
   *
   * @return the y coordinate
   */
  public double getY() {
    return y;
  }

  /**
   * Gets the z coordinate.
   *
   * @return the z coordinate
   */
  public double getZ() {
    return z;
  }

  /**
   * Creates a new Vector3d with the specified x coordinate.
   *
   * @param x the new x coordinate
   * @return a new Vector3d
   */
  public Vector3d withX(double x) {
    return new Vector3d(x, this.y, this.z);
  }

  /**
   * Creates a new Vector3d with the specified y coordinate.
   *
   * @param y the new y coordinate
   * @return a new Vector3d
   */
  public Vector3d withY(double y) {
    return new Vector3d(this.x, y, this.z);
  }

  /**
   * Creates a new Vector3d with the specified z coordinate.
   *
   * @param z the new z coordinate
   * @return a new Vector3d
   */
  public Vector3d withZ(double z) {
    return new Vector3d(this.x, this.y, z);
  }

  /**
   * Adds another vector to this vector.
   *
   * @param other the other vector
   * @return a new Vector3d representing the sum
   */
  public Vector3d add(Vector3d other) {
    return new Vector3d(this.x + other.x, this.y + other.y, this.z + other.z);
  }

  /**
   * Subtracts another vector from this vector.
   *
   * @param other the other vector
   * @return a new Vector3d representing the difference
   */
  public Vector3d subtract(Vector3d other) {
    return new Vector3d(this.x - other.x, this.y - other.y, this.z - other.z);
  }

  /**
   * Multiplies this vector by a scalar.
   *
   * @param scalar the scalar value
   * @return a new Vector3d representing the scaled vector
   */
  public Vector3d multiply(double scalar) {
    return new Vector3d(this.x * scalar, this.y * scalar, this.z * scalar);
  }

  /**
   * Divides this vector by a scalar.
   *
   * @param scalar the scalar value
   * @return a new Vector3d representing the divided vector
   */
  public Vector3d divide(double scalar) {
    return new Vector3d(this.x / scalar, this.y / scalar, this.z / scalar);
  }

  /**
   * Calculates the dot product with another vector.
   *
   * @param other the other vector
   * @return the dot product
   */
  public double dot(Vector3d other) {
    return this.x * other.x + this.y * other.y + this.z * other.z;
  }

  /**
   * Calculates the cross product with another vector.
   *
   * @param other the other vector
   * @return a new Vector3d representing the cross product
   */
  public Vector3d cross(Vector3d other) {
    return new Vector3d(
        this.y * other.z - this.z * other.y,
        this.z * other.x - this.x * other.z,
        this.x * other.y - this.y * other.x
    );
  }

  /**
   * Calculates the length (magnitude) of this vector.
   *
   * @return the length of this vector
   */
  public double length() {
    return Math.sqrt(this.x * this.x + this.y * this.y + this.z * this.z);
  }

  /**
   * Calculates the squared length of this vector.
   *
   * @return the squared length of this vector
   */
  public double lengthSquared() {
    return this.x * this.x + this.y * this.y + this.z * this.z;
  }

  /**
   * Calculates the distance to another vector.
   *
   * @param other the other vector
   * @return the distance between the vectors
   */
  public double distance(Vector3d other) {
    return subtract(other).length();
  }

  /**
   * Calculates the squared distance to another vector.
   *
   * @param other the other vector
   * @return the squared distance between the vectors
   */
  public double distanceSquared(Vector3d other) {
    return subtract(other).lengthSquared();
  }

  /**
   * Normalizes this vector.
   *
   * @return a new Vector3d representing the normalized vector
   */
  public Vector3d normalize() {
    double length = length();
    if (length == 0) {
      return ZERO;
    }
    return divide(length);
  }

  /**
   * Linearly interpolates between this vector and another vector.
   *
   * @param other the other vector
   * @param t     the interpolation factor (0.0 to 1.0)
   * @return a new Vector3d representing the interpolated vector
   */
  public Vector3d lerp(Vector3d other, double t) {
    return new Vector3d(
        this.x + (other.x - this.x) * t,
        this.y + (other.y - this.y) * t,
        this.z + (other.z - this.z) * t
    );
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Vector3d)) {
      return false;
    }
    Vector3d vector3d = (Vector3d) o;
    return Double.compare(vector3d.x, x) == 0
        && Double.compare(vector3d.y, y) == 0
        && Double.compare(vector3d.z, z) == 0;
  }

  @Override
  public int hashCode() {
    return Objects.hash(x, y, z);
  }

  @Override
  public String toString() {
    return "Vector3d{x=" + x + ", y=" + y + ", z=" + z + '}';
  }
}