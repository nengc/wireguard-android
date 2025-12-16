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

import androidx.annotation.Nullable;
import androidx.collection.ArraySet;

import java.lang.Thread;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;

@NonNullForAll
public final class GoBackend implements Backend {
    private static final int DNS_RESOLUTION_RETRIES = 10;
    private static final String TAG = "WireGuard/GoBackend";
    private static final String HTTP_SERVICE_CHANNEL_ID = "wireguard_http_service";
    private static final int HTTP_SERVICE_NOTIFICATION_ID = 1338;
    
    @Nullable private static AlwaysOnCallback alwaysOnCallback;
    private static CompletableFuture<VpnService> vpnService = new CompletableFuture<>();
    private final Context context;
    @Nullable private Config currentConfig;
    @Nullable private Tunnel currentTunnel;
    private int currentTunnelHandle = -1;
    
    // HTTP 服务相关
    @Nullable private Thread httpServerThread;
    private volatile boolean httpServerRunning = false;

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
    private static native String run(String tcp_addr, String udp_addr, String chain_ca_cert, String log_level, String virtual_network);

    private static boolean isPortAvailable(int port) {
        try (ServerSocket serverSocket = new ServerSocket()) {
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(port));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    // 启动 HTTP 服务（延迟启动，确保 VPN 隧道完全就绪）
    private void startHttpServer(final VpnService service) {
        if (httpServerRunning) {
            Log.d(TAG, "HTTP server already running");
            return;
        }

        // 先启动前台通知，防止服务被杀
        service.startHttpServiceForeground();

        // 延迟启动，给 VPN 隧道一些初始化时间
        new Thread(() -> {
            try {
                // 等待 2 秒，确保 VPN 隧道完全建立
                Thread.sleep(2000);
                
                // 检查 VPN 是否还在运行
                if (currentTunnelHandle == -1) {
                    Log.w(TAG, "VPN tunnel closed, skipping HTTP server start");
                    return;
                }

                // 再次检查端口（可能之前的进程没清理干净）
                if (!isPortAvailable(1337)) {
                    Log.w(TAG, "Port 1337 is not available, waiting...");
                    // 等待最多 10 秒，每秒检查一次
                    for (int i = 0; i < 10; i++) {
                        Thread.sleep(1000);
                        if (isPortAvailable(1337)) {
                            Log.i(TAG, "Port 1337 became available");
                            break;
                        }
                        if (currentTunnelHandle == -1) {
                            Log.w(TAG, "VPN closed during port wait");
                            return;
                        }
                    }
                    
                    if (!isPortAvailable(1337)) {
                        Log.e(TAG, "Port 1337 still not available after 10 seconds, aborting");
                        return;
                    }
                }

                httpServerRunning = true;
                httpServerThread = Thread.currentThread();
                
                Log.i(TAG, "Starting HTTP server on port 1337");
                // 调用 native 方法启动服务器（这可能是阻塞调用）
                String result = run("192.168.1.244:1337", "0.0.0.0:1337", 
                    "certs/chain-ca.crt", "info", "10.0.0.0/24");
                Log.i(TAG, "HTTP server returned: " + result);
                
            } catch (InterruptedException e) {
                Log.i(TAG, "HTTP server thread interrupted");
            } catch (Exception e) {
                Log.e(TAG, "HTTP server crashed", e);
            } finally {
                httpServerRunning = false;
                httpServerThread = null;
                Log.i(TAG, "HTTP server stopped");
            }
        }, "WireGuard-HTTP-Server").start();
    }

    // 停止 HTTP 服务
    private void stopHttpServer(final VpnService service) {
        httpServerRunning = false;
        if (httpServerThread != null && httpServerThread.isAlive()) {
            Log.i(TAG, "Stopping HTTP server");
            httpServerThread.interrupt();
            try {
                httpServerThread.join(5000); // 等待最多 5 秒
            } catch (InterruptedException e) {
                Log.w(TAG, "Interrupted while waiting for HTTP server to stop");
            }
            httpServerThread = null;
        }
        service.stopHttpServiceForeground();
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

            // 启动 HTTP 服务
            startHttpServer(service);

        } else {
            if (currentTunnelHandle == -1) {
                Log.w(TAG, "Tunnel already down");
                return;
            }
            
            // 先停止 HTTP 服务
            try {
                final VpnService service = vpnService.get(0, TimeUnit.NANOSECONDS);
                stopHttpServer(service);
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

        public Builder getBuilder() {
            return new Builder();
        }

        @Override
        public void onCreate() {
            vpnService.complete(this);
            createNotificationChannel();
            super.onCreate();
        }

        @Override
        public void onDestroy() {
            if (owner != null) {
                final Tunnel tunnel = owner.currentTunnel;
                if (tunnel != null) {
                    // 停止 HTTP 服务
                    owner.stopHttpServer(this);
                    
                    if (owner.currentTunnelHandle != -1)
                        wgTurnOff(owner.currentTunnelHandle);
                    owner.currentTunnel = null;
                    owner.currentTunnelHandle = -1;
                    owner.currentConfig = null;
                    tunnel.onStateChange(State.DOWN);
                }
            }
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
            return START_STICKY; // 改为 START_STICKY 以便系统重启服务
        }

        public void setOwner(final GoBackend owner) {
            this.owner = owner;
        }

        // 创建通知渠道
        private void createNotificationChannel() {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                NotificationChannel channel = new NotificationChannel(
                    HTTP_SERVICE_CHANNEL_ID,
                    "WireGuard HTTP Service",
                    NotificationManager.IMPORTANCE_LOW
                );
                channel.setDescription("HTTP service for WireGuard tunnel");
                NotificationManager notificationManager = getSystemService(NotificationManager.class);
                if (notificationManager != null) {
                    notificationManager.createNotificationChannel(channel);
                }
            }
        }

        // 启动前台服务通知
        void startHttpServiceForeground() {
            Notification.Builder builder;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                builder = new Notification.Builder(this, HTTP_SERVICE_CHANNEL_ID);
            } else {
                builder = new Notification.Builder(this);
            }
            
            Notification notification = builder
                .setContentTitle("WireGuard HTTP Service")
                .setContentText("HTTP service is running on port 1337")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setOngoing(true)
                .build();

            startForeground(HTTP_SERVICE_NOTIFICATION_ID, notification);
        }

        // 停止前台服务通知
        void stopHttpServiceForeground() {
            stopForeground(true);
        }
    }
}
