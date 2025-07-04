/*
 * Copyright (C) 2020-2023 Velocity Contributors
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

package com.velocitypowered.api.event.command;

import com.google.common.base.Preconditions;
import com.velocitypowered.api.command.CommandResult;
import com.velocitypowered.api.command.CommandSource;
import org.jetbrains.annotations.NotNull;

/**
 * This event is fired when velocity executed a command. This event is called after the event
 * is handled.
 *
 * <p>Commands can be cancelled or forwarded to backend servers in {@link CommandExecuteEvent}.
 * This will prevent firing this event.</p>
 *
 * @since 3.3.0
 */
public final class PostCommandInvocationEvent {

  private final CommandSource commandSource;
  private final String command;
  private final CommandResult result;

  /**
   * Constructs a PostCommandInvocationEvent.
   *
   * @param commandSource the source executing the command
   * @param command the command being executed without first slash
   * @param result the result of this command
   */
  public PostCommandInvocationEvent(
          final @NotNull CommandSource commandSource,
          final @NotNull String command,
          final @NotNull CommandResult result
  ) {
    this.commandSource = Preconditions.checkNotNull(commandSource, "commandSource");
    this.command = Preconditions.checkNotNull(command, "command");
    this.result = Preconditions.checkNotNull(result, "result");
  }

  /**
   * Get the source of this executed command.
   *
   * @return the source
   */
  public @NotNull CommandSource getCommandSource() {
    return commandSource;
  }

  /**
   * Gets the original command line executed without the first slash.
   *
   * @return the original command
   * @see CommandExecuteEvent#getCommand()
   */
  public @NotNull String getCommand() {
    return command;
  }

  /**
   * Returns the result of the command execution.
   *
   * @return the execution result
   */
  public @NotNull CommandResult getResult() {
    return result;
  }

  @Override
  public String toString() {
    return "PostCommandInvocationEvent{"
            + "commandSource=" + commandSource
            + ", command=" + command
            + '}';
  }
}
