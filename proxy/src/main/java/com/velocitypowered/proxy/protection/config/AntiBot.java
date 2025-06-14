public class AntiBot {
    private final boolean enabled;
    private final Map<String, Object> checks;

    public AntiBot(boolean enabled, Map<String, Object> checks) {
        this.enabled = enabled;
        this.checks = checks;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public Map<String, Object> getChecks() {
        return checks;
    }
}