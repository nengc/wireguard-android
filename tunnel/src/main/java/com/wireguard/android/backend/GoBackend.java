/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.system.OsConstants;
import android.util.Log;

import com.wireguard.android.backend.BackendException.Reason;
import com.wireguard.android.backend.Tunnel.State;
import com.wireguard.android.util.SharedLibraryLoader;
import com.wireguard.config.Config;
import com.wireguard.config.InetEndpoint;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Peer;
import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;
import com.wireguard.util.NonNullForAll;

import java.net.InetAddress;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import androidx.annotation.Nullable;
import androidx.collection.ArraySet;

import java.lang.Thread;
import java.net.DatagramSocket;
import java.net.SocketException;

@NonNullForAll
public final class GoBackend implements Backend {
    private static final int DNS_RESOLUTION_RETRIES = 10;
    private static final String TAG = "WireGuard/GoBackend";
    private static final String UDP_SERVICE_CHANNEL_ID = "wireguard_udp_service";
    private static final int UDP_SERVICE_NOTIFICATION_ID = 1338;
    private static final int UDP_LISTEN_PORT = 1337;
    private static final int PORT_CHECK_MAX_RETRIES = 20;
    private static final long PORT_CHECK_INTERVAL_MS = 500;
    
    @Nullable private static AlwaysOnCallback alwaysOnCallback;
    private static CompletableFuture<VpnService> vpnService = new CompletableFuture<>();
    private final Context context;
    @Nullable private Config currentConfig;
    @Nullable private Tunnel currentTunnel;
    private int currentTunnelHandle = -1;
    
    // UDP 监听服务相关
    @Nullable private Thread udpServiceThread;
    private final AtomicBoolean udpServiceRunning = new AtomicBoolean(false);
    private final AtomicBoolean udpServiceShouldStop = new AtomicBoolean(false);
    private final AtomicInteger udpServiceHandle = new AtomicInteger(-1);

    public GoBackend(final Context context) {
        SharedLibraryLoader.loadSharedLibrary(context, "wg-go");
        SharedLibraryLoader.loadSharedLibrary(context, "u2t_tlcp_android");
        SharedLibraryLoader.loadSharedLibrary(context, "u2t_tlcp_jni");
        this.context = context;
    }

    public static void setAlwaysOnCallback(final AlwaysOnCallback cb) {
        alwaysOnCallback = cb;
    }

    @Nullable private static native String wgGetConfig(int handle);
    private static native int wgGetSocketV4(int handle);
    private static native int wgGetSocketV6(int handle);
    private static native void wgTurnOff(int handle);
    private static native int wgTurnOn(String ifName, int tunFd, String settings);
    private static native String wgVersion();
    
    // UDP 监听服务的 native 方法
    // 返回值：成功时返回服务标识，失败返回错误信息
    private static native String run(String tcp_addr, String udp_addr, String chain_ca_cert, String log_level, String virtual_network);
    
    // 如果你的 native 代码支持停止，添加这个方法
    // private static native void stopUdpService();

    /**
     * 检查 UDP 端口是否可用
     */
    private static boolean isUdpPortAvailable(int port) {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket(port);
            socket.setReuseAddress(true);
            return true;
        } catch (SocketException e) {
            Log.d(TAG, "Port " + port + " check failed: " + e.getMessage());
            return false;
        } finally {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        }
    }

    /**
     * 强制尝试释放 UDP 端口
     * 通过短暂绑定再关闭来触发系统释放端口
     */
    private void forceReleaseUdpPort(int port) {
        DatagramSocket socket = null;
        try {
            Log.d(TAG, "Attempting to force release UDP port " + port);
            socket = new DatagramSocket(null);
            socket.setReuseAddress(true);
            socket.bind(new java.net.InetSocketAddress(port));
            // 立即关闭
            socket.close();
            socket = null;
            
            // 给系统一点时间完全释放端口
            Thread.sleep(300);
            Log.d(TAG, "UDP port " + port + " force release completed");
        } catch (Exception e) {
            Log.w(TAG, "Failed to force release UDP port " + port + ": " + e.getMessage());
        } finally {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        }
    }

    /**
     * 等待 UDP 端口变为可用
     */
    private boolean waitForUdpPortAvailable(int port, int maxRetries) {
        Log.i(TAG, "Waiting for UDP port " + port + " to become available...");
        
        for (int i = 0; i < maxRetries; i++) {
            // 检查是否应该停止
            if (udpServiceShouldStop.get() || currentTunnelHandle == -1) {
                Log.i(TAG, "Port wait cancelled due to shutdown signal");
                return false;
            }
            
            if (isUdpPortAvailable(port)) {
                Log.i(TAG, "UDP port " + port + " is available (attempt " + (i + 1) + ")");
                return true;
            }
            
            // 第一次和第五次失败时尝试强制释放
            if (i == 0 || i == 5) {
                forceReleaseUdpPort(port);
            }
            
            Log.d(TAG, "UDP port " + port + " not available, retrying... (" + (i + 1) + "/" + maxRetries + ")");
            
            try {
                Thread.sleep(PORT_CHECK_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                Log.w(TAG, "Port wait interrupted");
                return false;
            }
        }
        
        Log.e(TAG, "UDP port " + port + " still not available after " + maxRetries + " attempts");
        return false;
    }

    /**
     * 启动 UDP 监听服务
     */
    private void startUdpService(final VpnService service) {
        if (udpServiceRunning.get()) {
            Log.w(TAG, "UDP service already running");
            return;
        }

        Log.i(TAG, "Starting UDP service...");
        udpServiceShouldStop.set(false);
        
        // 立即启动前台通知，防止被系统杀掉
        service.startUdpServiceForeground();

        // 创建独立线程运行 UDP 监听服务
        udpServiceThread = new Thread(() -> {
            try {
                // 等待 VPN 隧道完全建立并稳定
                Log.d(TAG, "Waiting for VPN tunnel to stabilize before starting UDP service...");
                Thread.sleep(2000);
                
                // 检查 VPN 和停止信号
                if (currentTunnelHandle == -1 || udpServiceShouldStop.get()) {
                    Log.w(TAG, "VPN tunnel closed or stop requested, aborting UDP service start");
                    return;
                }

                // 等待 UDP 端口可用
                Log.i(TAG, "Checking UDP port " + UDP_LISTEN_PORT + " availability...");
                if (!waitForUdpPortAvailable(UDP_LISTEN_PORT, PORT_CHECK_MAX_RETRIES)) {
                    Log.e(TAG, "Cannot start UDP service: port " + UDP_LISTEN_PORT + " unavailable");
                    service.updateNotification("UDP service failed: port unavailable");
                    return;
                }

                // 最后一次检查状态
                if (currentTunnelHandle == -1 || udpServiceShouldStop.get()) {
                    Log.w(TAG, "VPN closed or stop requested during port wait");
                    return;
                }

                // 标记服务正在运行
                udpServiceRunning.set(true);
                service.updateNotification("UDP service running on port " + UDP_LISTEN_PORT);
                
                Log.i(TAG, "Starting UDP listener on port " + UDP_LISTEN_PORT);
                
                // 调用 native 方法启动 UDP 监听（这是阻塞调用）
                // run() 会一直阻塞直到服务停止或出错
                String result = run(
                    "192.168.1.244:" + UDP_LISTEN_PORT,  // TCP 地址（如果需要）
                    "0.0.0.0:" + UDP_LISTEN_PORT,        // UDP 监听地址
                    "certs/chain-ca.crt",                // 证书路径
                    "info",                              // 日志级别
                    "10.0.0.0/24"                       // 虚拟网络
                );
                
                Log.i(TAG, "UDP service exited: " + result);
                
            } catch (InterruptedException e) {
                Log.i(TAG, "UDP service thread interrupted");
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                Log.e(TAG, "UDP service crashed with exception", e);
                try {
                    final VpnService svc = vpnService.get(0, TimeUnit.NANOSECONDS);
                    svc.updateNotification("UDP service error: " + e.getMessage());
                } catch (Exception ignored) { }
            } finally {
                udpServiceRunning.set(false);
                Log.i(TAG, "UDP service thread finished");
                
                // 确保端口被完全释放
                forceReleaseUdpPort(UDP_LISTEN_PORT);
                
                // 更新通知状态
                try {
                    final VpnService svc = vpnService.get(0, TimeUnit.NANOSECONDS);
                    svc.updateNotification("UDP service stopped");
                } catch (Exception ignored) { }
            }
        }, "WireGuard-UDP-Listener");
        
        udpServiceThread.setDaemon(false);  // 不设为守护线程，确保不会被意外终止
        udpServiceThread.setPriority(Thread.NORM_PRIORITY + 1);  // 稍微提高优先级
        
        // 设置未捕获异常处理器
        udpServiceThread.setUncaughtExceptionHandler((t, e) -> {
            Log.e(TAG, "Uncaught exception in UDP service thread", e);
            udpServiceRunning.set(false);
            forceReleaseUdpPort(UDP_LISTEN_PORT);
        });
        
        udpServiceThread.start();
        Log.i(TAG, "UDP service thread started");
    }

    /**
     * 停止 UDP 监听服务
     */
    private void stopUdpService(final VpnService service) {
        Log.i(TAG, "Stopping UDP service...");
        
        // 设置停止标志
        udpServiceShouldStop.set(true);
        udpServiceRunning.set(false);
        
        // 如果你的 native 代码支持停止信号，在这里调用
        // stopUdpService();
        
        Thread threadToStop = udpServiceThread;
        if (threadToStop != null && threadToStop.isAlive()) {
            Log.d(TAG, "Interrupting UDP service thread...");
            threadToStop.interrupt();
            
            try {
                // 等待线程优雅退出
                threadToStop.join(5000);
                
                if (threadToStop.isAlive()) {
                    Log.w(TAG, "UDP service thread still alive after 5s");
                    // 再次尝试中断
                    threadToStop.interrupt();
                    threadToStop.join(2000);
                    
                    if (threadToStop.isAlive()) {
                        Log.e(TAG, "UDP service thread forcefully abandoned");
                    }
                }
            } catch (InterruptedException e) {
                Log.w(TAG, "Interrupted while waiting for UDP service to stop");
                Thread.currentThread().interrupt();
            }
        }
        
        udpServiceThread = null;
        
        // 强制释放 UDP 端口
        forceReleaseUdpPort(UDP_LISTEN_PORT);
        
        // 停止前台服务通知
        service.stopUdpServiceForeground();
        
        Log.i(TAG, "UDP service stopped completely");
    }

    @Override
    public Set<String> getRunningTunnelNames() {
        if (currentTunnel != null) {
            final Set<String> runningTunnels = new ArraySet<>();
            runningTunnels.add(currentTunnel.getName());
            return runningTunnels;
        }
        return Collections.emptySet();
    }

    @Override
    public State getState(final Tunnel tunnel) {
        return currentTunnel == tunnel ? State.UP : State.DOWN;
    }

    @Override
    public Statistics getStatistics(final Tunnel tunnel) {
        final Statistics stats = new Statistics();
        if (tunnel != currentTunnel || currentTunnelHandle == -1)
            return stats;
        final String config = wgGetConfig(currentTunnelHandle);
        if (config == null)
            return stats;
        Key key = null;
        long rx = 0;
        long tx = 0;
        long latestHandshakeMSec = 0;
        for (final String line : config.split("\\n")) {
            if (line.startsWith("public_key=")) {
                if (key != null)
                    stats.add(key, rx, tx, latestHandshakeMSec);
                rx = 0;
                tx = 0;
                latestHandshakeMSec = 0;
                try {
                    key = Key.fromHex(line.substring(11));
                } catch (final KeyFormatException ignored) {
                    key = null;
                }
            } else if (line.startsWith("rx_bytes=")) {
                if (key == null)
                    continue;
                try {
                    rx = Long.parseLong(line.substring(9));
                } catch (final NumberFormatException ignored) {
                    rx = 0;
                }
            } else if (line.startsWith("tx_bytes=")) {
                if (key == null)
                    continue;
                try {
                    tx = Long.parseLong(line.substring(9));
                } catch (final NumberFormatException ignored) {
                    tx = 0;
                }
            } else if (line.startsWith("last_handshake_time_sec=")) {
                if (key == null)
                    continue;
                try {
                    latestHandshakeMSec += Long.parseLong(line.substring(24)) * 1000;
                } catch (final NumberFormatException ignored) {
                    latestHandshakeMSec = 0;
                }
            } else if (line.startsWith("last_handshake_time_nsec=")) {
                if (key == null)
                    continue;
                try {
                    latestHandshakeMSec += Long.parseLong(line.substring(25)) / 1000000;
                } catch (final NumberFormatException ignored) {
                    latestHandshakeMSec = 0;
                }
            }
        }
        if (key != null)
            stats.add(key, rx, tx, latestHandshakeMSec);
        return stats;
    }

    @Override
    public String getVersion() {
        return wgVersion();
    }

    @Override
    public boolean isAlwaysOn() throws ExecutionException, InterruptedException, TimeoutException {
        return vpnService.get(0, TimeUnit.NANOSECONDS).isAlwaysOn();
    }

    @Override
    public boolean isLockdownEnabled() throws ExecutionException, InterruptedException, TimeoutException {
        return vpnService.get(0, TimeUnit.NANOSECONDS).isLockdownEnabled();
    }

    @Override
    public State setState(final Tunnel tunnel, State state, @Nullable final Config config) throws Exception {
        final State originalState = getState(tunnel);

        if (state == State.TOGGLE)
            state = originalState == State.UP ? State.DOWN : State.UP;
        if (state == originalState && tunnel == currentTunnel && config == currentConfig)
            return originalState;
        if (state == State.UP) {
            final Config originalConfig = currentConfig;
            final Tunnel originalTunnel = currentTunnel;
            if (currentTunnel != null)
                setStateInternal(currentTunnel, null, State.DOWN);
            try {
                setStateInternal(tunnel, config, state);
            } catch (final Exception e) {
                if (originalTunnel != null)
                    setStateInternal(originalTunnel, originalConfig, State.UP);
                throw e;
            }
        } else if (state == State.DOWN && tunnel == currentTunnel) {
            setStateInternal(tunnel, null, State.DOWN);
        }
        return getState(tunnel);
    }

    private void setStateInternal(final Tunnel tunnel, @Nullable final Config config, final State state)
            throws Exception {
        Log.i(TAG, "Bringing tunnel " + tunnel.getName() + ' ' + state);

        if (state == State.UP) {
            if (config == null)
                throw new BackendException(Reason.TUNNEL_MISSING_CONFIG);

            if (VpnService.prepare(context) != null)
                throw new BackendException(Reason.VPN_NOT_AUTHORIZED);

            final VpnService service;
            if (!vpnService.isDone()) {
                Log.d(TAG, "Requesting to start VpnService");
                context.startService(new Intent(context, VpnService.class));
            }

            try {
                service = vpnService.get(2, TimeUnit.SECONDS);
            } catch (final TimeoutException e) {
                final Exception be = new BackendException(Reason.UNABLE_TO_START_VPN);
                be.initCause(e);
                throw be;
            }
            service.setOwner(this);

            if (currentTunnelHandle != -1) {
                Log.w(TAG, "Tunnel already up");
                return;
            }

            dnsRetry: for (int i = 0; i < DNS_RESOLUTION_RETRIES; ++i) {
                for (final Peer peer : config.getPeers()) {
                    final InetEndpoint ep = peer.getEndpoint().orElse(null);
                    if (ep == null)
                        continue;
                    if (ep.getResolved().orElse(null) == null) {
                        if (i < DNS_RESOLUTION_RETRIES - 1) {
                            Log.w(TAG, "DNS host \"" + ep.getHost() + "\" failed to resolve; trying again");
                            Thread.sleep(1000);
                            continue dnsRetry;
                        } else
                            throw new BackendException(Reason.DNS_RESOLUTION_FAILURE, ep.getHost());
                    }
                }
                break;
            }

            final String goConfig = config.toWgUserspaceString();
            final VpnService.Builder builder = service.getBuilder();
            builder.setSession(tunnel.getName());

            for (final String excludedApplication : config.getInterface().getExcludedApplications())
                builder.addDisallowedApplication(excludedApplication);

            for (final String includedApplication : config.getInterface().getIncludedApplications())
                builder.addAllowedApplication(includedApplication);

            for (final InetNetwork addr : config.getInterface().getAddresses())
                builder.addAddress(addr.getAddress(), addr.getMask());

            for (final InetAddress addr : config.getInterface().getDnsServers())
                builder.addDnsServer(addr.getHostAddress());

            for (final String dnsSearchDomain : config.getInterface().getDnsSearchDomains())
                builder.addSearchDomain(dnsSearchDomain);

            boolean sawDefaultRoute = false;
            for (final Peer peer : config.getPeers()) {
                for (final InetNetwork addr : peer.getAllowedIps()) {
                    if (addr.getMask() == 0)
                        sawDefaultRoute = true;
                    builder.addRoute(addr.getAddress(), addr.getMask());
                }
            }

            if (!(sawDefaultRoute && config.getPeers().size() == 1)) {
                builder.allowFamily(OsConstants.AF_INET);
                builder.allowFamily(OsConstants.AF_INET6);
            }

            builder.setMtu(config.getInterface().getMtu().orElse(1280));

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                builder.setMetered(false);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                service.setUnderlyingNetworks(null);

            builder.setBlocking(true);
            try (final ParcelFileDescriptor tun = builder.establish()) {
                if (tun == null)
                    throw new BackendException(Reason.TUN_CREATION_ERROR);
                Log.d(TAG, "Go backend " + wgVersion());
                currentTunnelHandle = wgTurnOn(tunnel.getName(), tun.detachFd(), goConfig);
            }
            if (currentTunnelHandle < 0)
                throw new BackendException(Reason.GO_ACTIVATION_ERROR_CODE, currentTunnelHandle);

            currentTunnel = tunnel;
            currentConfig = config;

            service.protect(wgGetSocketV4(currentTunnelHandle));
            service.protect(wgGetSocketV6(currentTunnelHandle));

            // 启动 UDP 监听服务
            startUdpService(service);

        } else {
            if (currentTunnelHandle == -1) {
                Log.w(TAG, "Tunnel already down");
                return;
            }
            
            // 先停止 UDP 监听服务
            try {
                final VpnService service = vpnService.get(0, TimeUnit.NANOSECONDS);
                stopUdpService(service);
            } catch (final TimeoutException ignored) { }
            
            int handleToClose = currentTunnelHandle;
            currentTunnel = null;
            currentTunnelHandle = -1;
            currentConfig = null;
            wgTurnOff(handleToClose);
            
            try {
                vpnService.get(0, TimeUnit.NANOSECONDS).stopSelf();
            } catch (final TimeoutException ignored) { }
        }

        tunnel.onStateChange(state);
    }

    public interface AlwaysOnCallback {
        void alwaysOnTriggered();
    }

    public static class VpnService extends android.net.VpnService {
        @Nullable private GoBackend owner;
        @Nullable private PowerManager.WakeLock wakeLock;

        public Builder getBuilder() {
            return new Builder();
        }

        @Override
        public void onCreate() {
            vpnService.complete(this);
            createNotificationChannel();
            acquireWakeLock();
            super.onCreate();
        }

        @Override
        public void onDestroy() {
            if (owner != null) {
                final Tunnel tunnel = owner.currentTunnel;
                if (tunnel != null) {
                    // 停止 UDP 监听服务
                    owner.stopUdpService(this);
                    
                    if (owner.currentTunnelHandle != -1)
                        wgTurnOff(owner.currentTunnelHandle);
                    owner.currentTunnel = null;
                    owner.currentTunnelHandle = -1;
                    owner.currentConfig = null;
                    tunnel.onStateChange(State.DOWN);
                }
            }
            
            releaseWakeLock();
            vpnService = vpnService.newIncompleteFuture();
            super.onDestroy();
        }

        @Override
        public int onStartCommand(@Nullable final Intent intent, final int flags, final int startId) {
            vpnService.complete(this);
            if (intent == null || intent.getComponent() == null || !intent.getComponent().getPackageName().equals(getPackageName())) {
                Log.d(TAG, "Service started by Always-on VPN feature");
                if (alwaysOnCallback != null)
                    alwaysOnCallback.alwaysOnTriggered();
            }
            return START_STICKY;
        }

        @Override
        public void onRevoke() {
            Log.w(TAG, "VPN service revoked by user");
            if (owner != null) {
                owner.stopUdpService(this);
            }
            super.onRevoke();
        }

        public void setOwner(final GoBackend owner) {
            this.owner = owner;
        }

        private void acquireWakeLock() {
            if (wakeLock == null) {
                PowerManager powerManager = (PowerManager) getSystemService(Context.POWER_SERVICE);
                if (powerManager != null) {
                    wakeLock = powerManager.newWakeLock(
                        PowerManager.PARTIAL_WAKE_LOCK,
                        "WireGuard:UdpService"
                    );
                    wakeLock.acquire();
                    Log.d(TAG, "WakeLock acquired for UDP service");
                }
            }
        }

        private void releaseWakeLock() {
            if (wakeLock != null && wakeLock.isHeld()) {
                wakeLock.release();
                wakeLock = null;
                Log.d(TAG, "WakeLock released");
            }
        }

        private void createNotificationChannel() {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                NotificationChannel channel = new NotificationChannel(
                    UDP_SERVICE_CHANNEL_ID,
                    "WireGuard UDP Service",
                    NotificationManager.IMPORTANCE_LOW
                );
                channel.setDescription("UDP listener service for WireGuard tunnel");
                channel.setShowBadge(false);
                channel.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
                
                NotificationManager notificationManager = getSystemService(NotificationManager.class);
                if (notificationManager != null) {
                    notificationManager.createNotificationChannel(channel);
                }
            }
        }

        void startUdpServiceForeground() {
            Notification.Builder builder;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                builder = new Notification.Builder(this, UDP_SERVICE_CHANNEL_ID);
            } else {
                builder = new Notification.Builder(this);
            }
            
            Notification notification = builder
                .setContentTitle("WireGuard UDP Service")
                .setContentText("UDP listener on port " + UDP_LISTEN_PORT)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setOngoing(true)
                .setShowWhen(true)
                .build();

            startForeground(UDP_SERVICE_NOTIFICATION_ID, notification);
            Log.d(TAG, "UDP service foreground started");
        }

        void updateNotification(String statusText) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
                return;
            }
            
            Notification.Builder builder = new Notification.Builder(this, UDP_SERVICE_CHANNEL_ID);
            Notification notification = builder
                .setContentTitle("WireGuard UDP Service")
                .setContentText(statusText)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setOngoing(true)
                .setShowWhen(true)
                .build();

            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            if (notificationManager != null) {
                notificationManager.notify(UDP_SERVICE_NOTIFICATION_ID, notification);
            }
        }

        void stopUdpServiceForeground() {
            stopForeground(true);
            Log.d(TAG, "UDP service foreground stopped");
        }
    }
}
