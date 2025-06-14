/*
 * Copyright (C) 2018-2023 Velocity Contributors
 * Current Date and Time (UTC): 2025-06-13 18:23:41
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security.rules;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Predicate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class BaseSecurityRule<T extends SecurityContext> implements SecurityRule<T> {
    private static final Logger logger = LogManager.getLogger(BaseSecurityRule.class);
    
    protected final String name;
    protected final List<Predicate<T>> conditions;
    protected final List<Consumer<T>> actions;
    protected boolean enabled;

    protected BaseSecurityRule(String name) {
        this.name = name;
        this.conditions = new ArrayList<>();
        this.actions = new ArrayList<>();
        this.enabled = true;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public SecurityRule<T> condition(Predicate<T> condition) {
        conditions.add(condition);
        return this;
    }

    @Override
    public SecurityRule<T> action(Consumer<T> action) {
        actions.add(action);
        return this;
    }

    @Override
    public boolean evaluate(T context) {
        if (!enabled) {
            return true;
        }

        try {
            // Check all conditions
            for (Predicate<T> condition : conditions) {
                if (!condition.test(context)) {
                    onViolation(context);
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            logger.error("Error evaluating rule: " + name, e);
            return false;
        }
    }

    @Override
    public void onViolation(T context) {
        try {
            // Execute all actions
            for (Consumer<T> action : actions) {
                action.accept(context);
            }
        } catch (Exception e) {
            logger.error("Error executing rule actions: " + name, e);
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}