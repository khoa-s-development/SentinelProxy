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
 *
 * Current Date and Time (UTC): 2025-06-14 10:26:31
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.protection.rules;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

public class RulesEngine {
    private static final Logger logger = LogManager.getLogger(RulesEngine.class);

    // Rule components
    private final RuleEvaluator ruleEvaluator;
    private final RuleCompiler ruleCompiler;
    private final ActionExecutor actionExecutor;
    private final ConditionMatcher conditionMatcher;

    // Rule collections
    private final Map<String, Rule> activeRules;
    private final Map<String, RuleSet> ruleSets;
    private final Cache<InetAddress, RuleContext> ruleContexts;
    private final Map<String, AtomicInteger> ruleStats;

    // Configuration
    private final int maxRulesPerSet;
    private final Duration contextExpiry;
    private final int maxContextSize;
    private final boolean strictMode;

    public RulesEngine() {
        // Initialize components
        this.ruleEvaluator = new RuleEvaluator();
        this.ruleCompiler = new RuleCompiler();
        this.actionExecutor = new ActionExecutor();
        this.conditionMatcher = new ConditionMatcher();

        // Initialize collections
        this.activeRules = new ConcurrentHashMap<>();
        this.ruleSets = new ConcurrentHashMap<>();
        this.ruleContexts = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();
        this.ruleStats = new ConcurrentHashMap<>();

        // Load configuration
        this.maxRulesPerSet = 50;
        this.contextExpiry = Duration.ofHours(1);
        this.maxContextSize = 1000;
        this.strictMode = true;

        // Register default rules
        registerDefaultRules();

        // Start maintenance tasks
        startMaintenanceTasks();
    }

    public RuleResult evaluateRules(InetAddress address, Map<String, Object> facts) {
        try {
            // Get or create rule context
            RuleContext context = getRuleContext(address);

            // Update context with new facts
            context.updateFacts(facts);

            // Evaluate each rule set
            List<RuleAction> actions = new ArrayList<>();
            boolean blocked = false;

            for (RuleSet ruleSet : ruleSets.values()) {
                RuleResult result = ruleSet.evaluate(context);
                if (result.isBlocked()) {
                    blocked = true;
                    updateStats(ruleSet.getName(), "blocked");
                } else {
                    updateStats(ruleSet.getName(), "passed");
                }
                actions.addAll(result.getActions());
            }

            // Execute actions
            actionExecutor.executeActions(actions, context);

            return new RuleResult(blocked, actions);

        } catch (Exception e) {
            logger.error("Error evaluating rules for " + address, e);
            return new RuleResult(strictMode, Collections.emptyList());
        }
    }

    private RuleContext getRuleContext(InetAddress address) {
        try {
            return ruleContexts.get(address, () -> new RuleContext());
        } catch (ExecutionException e) {
            logger.error("Error getting rule context", e);
            return new RuleContext();
        }
    }

    public void registerRule(String name, Rule rule) {
        try {
            rule = ruleCompiler.compile(rule);
            activeRules.put(name, rule);
            logger.info("Registered rule: {}", name);
        } catch (Exception e) {
            logger.error("Error registering rule: " + name, e);
        }
    }

    public void createRuleSet(String name, List<String> ruleNames) {
        if (ruleNames.size() > maxRulesPerSet) {
            throw new IllegalArgumentException("Too many rules in set");
        }

        List<Rule> rules = new ArrayList<>();
        for (String ruleName : ruleNames) {
            Rule rule = activeRules.get(ruleName);
            if (rule == null) {
                throw new IllegalArgumentException("Unknown rule: " + ruleName);
            }
            rules.add(rule);
        }

        RuleSet ruleSet = new RuleSet(name, rules);
        ruleSets.put(name, ruleSet);
        logger.info("Created rule set: {}", name);
    }

    private void registerDefaultRules() {
        // Rate limiting rules
        registerRule("rate.connection", new Rule.Builder()
            .condition("connection_rate > 100")
            .action("BLOCK")
            .build());

        registerRule("rate.packet", new Rule.Builder()
            .condition("packet_rate > 1000")
            .action("BLOCK")
            .build());

        // Pattern detection rules
        registerRule("pattern.sequence", new Rule.Builder()
            .condition("has_suspicious_sequence")
            .action("WARN")
            .build());

        registerRule("pattern.timing", new Rule.Builder()
            .condition("has_timing_anomaly")
            .action("LOG")
            .build());

        // Content validation rules
        registerRule("content.size", new Rule.Builder()
            .condition("content_size > 1048576")
            .action("BLOCK")
            .build());

        registerRule("content.pattern", new Rule.Builder()
            .condition("matches_malicious_pattern")
            .action("BLOCK")
            .build());
    }

    private void updateStats(String ruleName, String result) {
        String key = ruleName + "." + result;
        ruleStats.computeIfAbsent(key, k -> new AtomicInteger())
                 .incrementAndGet();
    }

    private void startMaintenanceTasks() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactoryBuilder()
                .setNameFormat("rules-engine-%d")
                .setDaemon(true)
                .build()
        );

        // Clean up old contexts
        executor.scheduleAtFixedRate(() -> {
            try {
                ruleContexts.cleanUp();
            } catch (Exception e) {
                logger.error("Error cleaning up rule contexts", e);
            }
        }, 1, 1, TimeUnit.HOURS);
    }

    private static class RuleSet {
        private final String name;
        private final List<Rule> rules;

        public RuleSet(String name, List<Rule> rules) {
            this.name = name;
            this.rules = new ArrayList<>(rules);
        }

        public RuleResult evaluate(RuleContext context) {
            List<RuleAction> actions = new ArrayList<>();
            boolean blocked = false;

            for (Rule rule : rules) {
                if (rule.evaluate(context)) {
                    RuleAction action = rule.getAction();
                    actions.add(action);
                    if (action.getType() == ActionType.BLOCK) {
                        blocked = true;
                    }
                }
            }

            return new RuleResult(blocked, actions);
        }

        public String getName() {
            return name;
        }
    }

    private static class RuleContext {
        private final Map<String, Object> facts;
        private final Queue<Map<String, Object>> history;
        private volatile long lastUpdate;

        public RuleContext() {
            this.facts = new ConcurrentHashMap<>();
            this.history = new ConcurrentLinkedQueue<>();
            this.lastUpdate = System.currentTimeMillis();
        }

        public void updateFacts(Map<String, Object> newFacts) {
            facts.putAll(newFacts);
            history.offer(new HashMap<>(newFacts));
            while (history.size() > 1000) {
                history.poll();
            }
            lastUpdate = System.currentTimeMillis();
        }

        public Object getFact(String name) {
            return facts.get(name);
        }

        public List<Map<String, Object>> getHistory() {
            return new ArrayList<>(history);
        }

        public long getLastUpdate() {
            return lastUpdate;
        }
    }

    private static class Rule {
        private final Condition condition;
        private final RuleAction action;

        private Rule(Condition condition, RuleAction action) {
            this.condition = condition;
            this.action = action;
        }

        public boolean evaluate(RuleContext context) {
            return condition.test(context);
        }

        public RuleAction getAction() {
            return action;
        }

        public static class Builder {
            private Condition condition;
            private RuleAction action;

            public Builder condition(String expression) {
                this.condition = ctx -> true; // Simplified
                return this;
            }

            public Builder action(String type) {
                this.action = new RuleAction(ActionType.valueOf(type));
                return this;
            }

            public Rule build() {
                return new Rule(condition, action);
            }
        }
    }

    @FunctionalInterface
    private interface Condition {
        boolean test(RuleContext context);
    }

    private static class RuleAction {
        private final ActionType type;

        public RuleAction(ActionType type) {
            this.type = type;
        }

        public ActionType getType() {
            return type;
        }
    }

    private enum ActionType {
        BLOCK,
        WARN,
        LOG
    }

    private static class RuleResult {
        private final boolean blocked;
        private final List<RuleAction> actions;

        public RuleResult(boolean blocked, List<RuleAction> actions) {
            this.blocked = blocked;
            this.actions = new ArrayList<>(actions);
        }

        public boolean isBlocked() {
            return blocked;
        }

        public List<RuleAction> getActions() {
            return actions;
        }
    }

    private static class RuleEvaluator {
        // Rule evaluation implementation
    }

    private static class RuleCompiler {
        public Rule compile(Rule rule) {
            return rule; // Simplified
        }
    }

    private static class ActionExecutor {
        public void executeActions(List<RuleAction> actions, RuleContext context) {
            // Action execution implementation
        }
    }

    private static class ConditionMatcher {
        // Condition matching implementation
    }

    // Stats and monitoring
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        
        Map<String, Integer> ruleCounts = new HashMap<>();
        ruleStats.forEach((key, count) -> 
            ruleCounts.put(key, count.get()));
        stats.put("rule_counts", ruleCounts);
        
        stats.put("active_contexts", ruleContexts.size());
        stats.put("active_sets", ruleSets.size());
        
        return stats;
    }

    public List<String> getActiveRules() {
        return new ArrayList<>(activeRules.keySet());
    }

    public List<String> getRuleSets() {
        return new ArrayList<>(ruleSets.keySet());
    }
}