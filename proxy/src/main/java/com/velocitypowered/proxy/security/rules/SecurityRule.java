/*
 * Copyright (C) 2018-2023 Velocity Contributors
 * Current Date and Time (UTC): 2025-06-13 18:23:41
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security.rules;

import java.util.function.Consumer;
import java.util.function.Predicate;

public interface SecurityRule<T extends SecurityContext> {
    String getName();
    boolean evaluate(T context);
    void onViolation(T context);
    String getMessage();
    SecurityRule<T> condition(Predicate<T> condition);
    SecurityRule<T> action(Consumer<T> action);
}