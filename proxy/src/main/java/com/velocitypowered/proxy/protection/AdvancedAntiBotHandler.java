package com.velocitypowered.proxy.protection;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.proxy.Player;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class AdvancedAntiBotHandler {
    private final Map<InetAddress, BotDetectionData> connectionData = new ConcurrentHashMap<>();
    private final Map<InetAddress, Integer> failedAttempts = new ConcurrentHashMap<>();
    private final Set<InetAddress> whitelisted = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Set<InetAddress> blacklisted = Collections.newSetFromMap(new ConcurrentHashMap<>());
    
    private boolean attackMode = false;
    private int threshold = 50; // Connections per minute threshold

    @Subscribe
    public void onPreLogin(PreLoginEvent event) {
        InetAddress address = event.getConnection().getRemoteAddress().getAddress();
        
        // Kiểm tra blacklist
        if (blacklisted.contains(address)) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied());
            return;
        }

        // Whitelist bypass
        if (whitelisted.contains(address)) {
            return;
        }

        // Kiểm tra bot patterns
        BotDetectionData data = connectionData.computeIfAbsent(
            address,
            k -> new BotDetectionData()
        );

        // Phân tích các dấu hiệu bot
        if (isBotBehavior(data, event)) {
            handleBotDetection(address);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied());
            return;
        }

        // Xử lý attack mode
        if (attackMode) {
            if (!data.isVerified()) {
                performVerification(event, address);
                return;
            }
        }

        data.recordConnection();
    }

    private boolean isBotBehavior(BotDetectionData data, PreLoginEvent event) {
        // Pattern 1: Tốc độ kết nối quá nhanh 
        if (data.getConnectionRate() > 10) { // >10 connections/second
            return true;
        }

        // Pattern 2: Nhiều tài khoản từ cùng IP
        if (data.getUniqueAccounts() > 3) { // >3 accounts/IP
            return true;
        }

        // Pattern 3: Kiểm tra username patterns
        String username = event.getUsername();
        if (isAutomatedUsername(username)) {
            return true;
        }

        // Pattern 4: Kiểm tra thời gian giữa các lần kết nối
        if (data.getAverageConnectionDelay() < 100) { // <100ms between connections
            return true;
        }

        return false;
    }

    private boolean isAutomatedUsername(String username) {
        // Kiểm tra username patterns thông thường của bot
        if (username.matches("^[a-zA-Z]\\d{6,}$")) return true; // vd: a123456
        if (username.matches("^Bot\\d+$")) return true; // vd: Bot123
        if (username.matches("^User\\d+$")) return true; // vd: User123
        if (username.matches("^\\d{8,}$")) return true; // vd: 12345678
        
        return false;
    }

    private void performVerification(PreLoginEvent event, InetAddress address) {
        // Thực hiện xác minh (có thể thêm CAPTCHA hoặc các phương thức khác)
        // Tạm thời chỉ delay connection
        try {
            Thread.sleep(2000); // 2s delay
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void handleBotDetection(InetAddress address) {
        failedAttempts.compute(address, (k, v) -> v == null ? 1 : v + 1);
        
        if (failedAttempts.get(address) > 3) {
            blacklisted.add(address);
        }
    }

    private static class BotDetectionData {
        private final Queue<Long> connectionTimes = new LinkedList<>();
        private final Set<String> uniqueAccounts = new HashSet<>();
        private boolean verified = false;

        public void recordConnection() {
            long now = System.currentTimeMillis();
            connectionTimes.offer(now);
            
            // Chỉ giữ lại 10 lần kết nối gần nhất
            while (connectionTimes.size() > 10) {
                connectionTimes.poll();
            }
        }

        public double getConnectionRate() {
            if (connectionTimes.size() < 2) return 0;
            
            long oldest = connectionTimes.peek();
            long newest = connectionTimes.peek();
            long duration = newest - oldest;
            
            return connectionTimes.size() / (duration / 1000.0);
        }

        public double getAverageConnectionDelay() {
            if (connectionTimes.size() < 2) return 1000.0;
            
            long sum = 0;
            long prev = -1;
            
            for (long time : connectionTimes) {
                if (prev != -1) {
                    sum += time - prev;
                }
                prev = time;
            }
            
            return sum / (double)(connectionTimes.size() - 1);
        }

        public int getUniqueAccounts() {
            return uniqueAccounts.size();
        }

        public void addAccount(String username) {
            uniqueAccounts.add(username.toLowerCase());
        }

        public boolean isVerified() {
            return verified;
        }

        public void setVerified(boolean verified) {
            this.verified = verified;
        }
    }

    // Cleanup task để chạy định kỳ
    public void cleanup() {
        long now = System.currentTimeMillis();
        
        // Xóa dữ liệu cũ
        connectionData.entrySet().removeIf(entry -> 
            now - entry.getValue().connectionTimes.peek() > TimeUnit.MINUTES.toMillis(5)
        );
        
        // Reset failed attempts
        failedAttempts.clear();
        
        // Cập nhật attack mode
        updateAttackMode();
    }

    private void updateAttackMode() {
        // Đếm số lượng connections trong phút vừa qua
        long connectionsLastMinute = connectionData.values().stream()
            .filter(data -> data.getConnectionRate() > 0)
            .count();
            
        attackMode = connectionsLastMinute > threshold;
    }
}
// testing
// This class is designed to be used in a Velocity proxy environment.