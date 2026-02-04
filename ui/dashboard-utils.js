(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.DashboardUtils = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    function toLower(value) {
        return (value || '').toLowerCase();
    }

    function normalizeHostName(raw) {
        if (!raw) return '';
        const trimmed = String(raw).trim();
        if (!trimmed) return '';
        const short = trimmed.split('.')[0].trim();
        return short.toUpperCase();
    }

    function normalizeServerRecord(server) {
        if (!server) return null;
        const normalizedName = normalizeHostName(server.name || server.server_name || '');
        if (!normalizedName) return null;
        const osType = normalizeOsType(server.os_type || server.os || server.osType);
        return {
            ...server,
            name: normalizedName,
            notes: server.notes || '',
            group: server.group || server.box || server.box_name || '',
            services: Array.isArray(server.services) ? server.services : [],
            os_type: osType,
        };
    }

    function normalizeOsType(raw) {
        const val = (raw || '').toString().trim().toLowerCase();
        if (val === 'linux' || val === 'lin') return 'Linux';
        return 'Windows';
    }

    function dedupeNormalizedServers(servers) {
        const seen = new Set();
        return (servers || []).filter((s) => {
            if (!s || !s.name) return false;
            const key = toLower(s.name);
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    }

    function hasDiskAlerts(server) {
        if (!server?.online || server?.data?.winrm_issue) return false;
        const alerts = server?.data?.disk_alerts;
        return Array.isArray(alerts) && alerts.length > 0;
    }

    function stoppedServices(server) {
        const services = server?.data?.service_status;
        if (!Array.isArray(services)) return 0;
        return services.filter((s) => {
            if (!s || !s.status) return false; // Skip services without status
            const status = toLower(s.status);
            // Exclude "NotFound" services - these are platform-specific services that don't exist on this host
            if (status === 'notfound') return false;
            return status !== 'running';
        }).length;
    }

    function hasServiceIssues(server) {
        if (!server?.online || server?.data?.winrm_issue) return false;
        return stoppedServices(server) > 0;
    }

    function hasWinrmIssue(server) {
        if (!server) return false;
        const heartbeatIssue = server?.heartbeat && server.heartbeat.winrm_ok === false;
        // Only count when host is reachable but WinRM data is degraded
        return !!(server.online && (server?.data?.winrm_issue || heartbeatIssue));
    }

    function hasHighCpu(server) {
        if (!server?.online) return false;
        const high = server?.data?.high_cpu_processes;
        const threshold = typeof server?.data?.high_cpu_threshold === 'number' ? server.data.high_cpu_threshold : 90;
        const hasHighList = Array.isArray(high) && high.some(p => typeof p.cpu_percent === 'number' && p.cpu_percent > threshold);
        const cpuLoad = server?.data?.uptime?.cpu_load_pct;
        const hasHighLoad = typeof cpuLoad === 'number' && cpuLoad > threshold;
        return hasHighList || hasHighLoad;
    }

    function hasHighMemory(server) {
        if (!server?.online) return false;
        const pct = server?.data?.memory_used_percent;
        return typeof pct === 'number' && pct >= 80;
    }

    function needsReboot(server) {
        if (!server?.online) return false;
        return !!server?.data?.pending_reboot?.pending;
    }

    function summarize(servers) {
        const total = servers.length;
        let online = 0;
        let diskWarnings = 0;
        let serviceIssues = 0;
        let winrmIssues = 0;
        let highCpu = 0;
        let highMemory = 0;
        let rebootNeeded = 0;

        servers.forEach((server) => {
            if (server.online) {
                online += 1;
            }
            if (hasDiskAlerts(server)) {
                diskWarnings += 1;
            }
            if (hasServiceIssues(server)) {
                serviceIssues += 1;
            }
            if (hasWinrmIssue(server)) {
                winrmIssues += 1;
            }
            if (hasHighCpu(server)) {
                highCpu += 1;
            }
            if (hasHighMemory(server)) {
                highMemory += 1;
            }
            if (needsReboot(server)) {
                rebootNeeded += 1;
            }
        });

        return {
            total,
            online,
            offline: total - online,
            diskWarnings,
            serviceIssues,
            winrmIssues,
            highCpu,
            highMemory,
            rebootNeeded
        };
    }

    function matchesTerm(server, term) {
        const normalized = term.trim().toLowerCase();
        if (!normalized) return true;

        const parts = [];
        parts.push(server?.name, server?.notes, server?.location);

        if (Array.isArray(server?.services)) {
            parts.push(...server.services);
        }

        const data = server?.data || {};
        if (data.os_info) {
            parts.push(data.os_info.os_version, data.os_info.product_type, data.os_info.computer_name);
        }

        if (data.uptime) {
            parts.push(data.uptime.last_boot, data.uptime.uptime_hours, data.uptime.cpu_load_pct);
        }

        if (data.pending_reboot) {
            parts.push(data.pending_reboot.pending, ...(data.pending_reboot.signals || []));
        }

        if (Array.isArray(data.winrm_listeners)) {
            data.winrm_listeners.forEach(l => parts.push(l.transport, l.address, l.port, l.hostname, l.certificate_thumbprint));
        }

        if (Array.isArray(data.firewall_profiles)) {
            data.firewall_profiles.forEach(p => parts.push(p.name, p.enabled, p.default_inbound_action, p.default_outbound_action));
        }

        if (Array.isArray(data.recent_errors)) {
            data.recent_errors.forEach(e => parts.push(e.log, e.id, e.provider, e.level, e.message));
        }

        if (Array.isArray(data.net_adapters)) {
            data.net_adapters.forEach(a => {
                parts.push(a.alias, a.description);
                if (Array.isArray(a.ipv4)) parts.push(...a.ipv4);
                if (Array.isArray(a.ipv6)) parts.push(...a.ipv6);
                if (Array.isArray(a.dns)) parts.push(...a.dns);
            });
        }

        if (Array.isArray(data.disks)) {
            data.disks.forEach(d => {
                parts.push(d.drive, d.volume_label, d.percent_free, d.free_gb, d.total_gb);
            });
        }

        if (Array.isArray(data.service_status)) {
            data.service_status.forEach(s => {
                parts.push(s.name, s.status);
            });
        }

        if (data.winrm_error) {
            parts.push(data.winrm_error);
        }

        if (server?.error) {
            parts.push(server.error);
        }

        parts.push(server?.online ? 'online' : 'offline');

        return parts.some(value => {
            if (value === undefined || value === null) return false;
            const text = String(value).toLowerCase();
            return text.includes(normalized);
        });
    }

    function matchesSummary(server, summaryFilter, term) {
        const filterType = typeof summaryFilter === 'string'
            ? summaryFilter
            : summaryFilter?.type;

        if (!filterType) return true;
        const hasSearch = !!(term && term.trim());
        switch (filterType) {
            case 'online':
                // Without a search term, treat WinRM-issue hosts as not cleanly online;
                // with a search term, include them to satisfy targeted lookups.
                return hasSearch ? !!server.online : (!!server.online && !hasWinrmIssue(server));
            case 'offline':
                return !server.online;
            case 'diskWarnings':
                return hasDiskAlerts(server);
            case 'serviceIssues':
                return hasServiceIssues(server);
            case 'winrmIssues':
                return hasWinrmIssue(server);
            case 'highCpu':
                return hasHighCpu(server);
            case 'highMemory':
                return hasHighMemory(server);
            case 'rebootNeeded':
                return needsReboot(server);
            default:
                return true;
        }
    }

    function filterServers(servers, term, summaryFilter) {
        const termOrEmpty = term || '';
        return servers.filter((server) => matchesTerm(server, termOrEmpty) && matchesSummary(server, summaryFilter, termOrEmpty));
    }

    return {
        summarize,
        filterServers,
        hasDiskAlerts,
        hasServiceIssues,
        hasWinrmIssue,
        hasHighCpu,
        hasHighMemory,
        needsReboot,
        stoppedServices,
        normalizeHostName,
        normalizeServerRecord,
        dedupeNormalizedServers,
        normalizeOsType
    };
}));
