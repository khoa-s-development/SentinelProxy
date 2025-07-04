/*
 * Copyright (C) 2020-2021 Velocity Contributors
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

package com.velocitypowered.api.command;

/**
 * The result of a command invocation attempt.
 */
public enum CommandResult {
  /**
   * The command was successfully executed by the proxy.
   */
  EXECUTED,
  /**
   * The command was forwarded to the backend server.
   * The command may be successfully executed or not
   */
  FORWARDED,
  /**
   * The provided command input contained syntax errors.
   */
  SYNTAX_ERROR,
  /**
   * An unexpected exception occurred while executing the command in the proxy.
   */
  EXCEPTION
}
