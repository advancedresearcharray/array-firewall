/** Gaming ops, policies, and sentinel embed for array-firewall dashboard. */
(function (global) {
  let api, $, showError, toast;
  let connPage = 0;
  let connPageSize = 25;
  let connTotal = 0;
  const selectedConn = new Set();
  const selectedPeers = new Set();

  function badge(cls, text) {
    return `<span class="badge ${cls}">${text}</span>`;
  }

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/"/g, '&quot;');
  }

  function setHtml(id, html) {
    const el = $(id);
    if (el) el.innerHTML = html;
  }

  function setText(id, t) {
    const el = $(id);
    if (el) el.textContent = t ?? '—';
  }

  async function refreshUploadAssist() {
    if (!$('goUploadActive')) return;
    try {
      const [ub, shaping] = await Promise.all([
        api('/api/v1/qos/upload-boost'),
        api('/api/v1/qos/shaping'),
      ]);
      const active = !!ub.active;
      setHtml('goUploadActive', active ? badge('ok', 'active') : badge('warn', 'off'));
      const st = ub.state || {};
      setText('goUploadShaped', st.shaped_mbps ? `${st.shaped_mbps} Mbps` : '—');
      setText('goUploadXboxCeil', st.xbox_ceil || '—');
      setText('goUploadOtherCeil', st.other_ceil || '—');
      const tc = ub.tc_xbox_class || '—';
      setText('goUploadTc', tc.length > 80 ? tc.slice(0, 80) + '…' : tc);
      const qUp = (shaping.queues || shaping.interfaces || {}).egress_upload
        || (shaping.interfaces || {}).upload || {};
      const grade = qUp.buffer_grade || (qUp.healthy === false ? 'fair' : 'unknown');
      setHtml('goQueueGrade', grade === 'excellent' || grade === 'good'
        ? badge('ok', grade) : badge('warn', grade));
      setText('goQueueBacklog', qUp.backlog_bytes != null ? `${qUp.backlog_bytes} B` : '—');
    } catch (e) {
      setHtml('goUploadActive', badge('bad', 'error'));
    }
  }

  async function refreshDefenses() {
    if (!$('goBufferMode')) return;
    try {
      const raw = await api('/api/v1/sentinel/dashboard-data');
      const d = raw.data || raw;
      const ng = d.network_guard || {};
      const ua = ng.upload_assist || {};
      setText('goBufferMode', ng.mode || '—');
      setHtml('goBufferEngage', ng.engage ? badge('warn', 'engaged') : badge('ok', 'idle'));
      setText('goFloodGuard', (ng.flood_guard || {}).level || 'off');
      setHtml('goMocaQos', (ng.moca_qos || {}).active ? badge('ok', 'EF') : badge('warn', 'off'));
      setHtml('goInMatchShield', (ng.packet_shield || {}).in_match_mode
        ? badge('ok', 'in-match') : ((ng.packet_shield || {}).active ? badge('warn', 'shield') : badge('ok', 'off')));
      setText('goUploadUtil', ua.utilization_pct != null ? `${ua.utilization_pct}%` : '—');
      setText('goUploadEgress', ua.egress_mbps != null ? `${ua.egress_mbps} Mbps` : '—');
      const alerts = ua.alerts || [];
      setHtml('goUploadAlerts', alerts.length
        ? `<ul class="reasons">${alerts.map(a => `<li>${esc(a)}</li>`).join('')}</ul>`
        : '<span class="sub">No upload pressure</span>');
      setText('goMitigation', ng.mitigation || '—');
    } catch (e) {
      setText('goBufferMode', 'offline');
    }
  }

  async function loadConnSessions() {
    const sel = $('goConnSession');
    if (!sel || sel.dataset.loaded === '1') return;
    try {
      const r = await api('/api/v1/gaming/connections/sessions?limit=40');
      (r.sessions || []).forEach(s => {
        const o = document.createElement('option');
        o.value = s.session_hex || '';
        o.textContent = `${(s.session_hex || '').slice(0, 12)}… · ${s.phase || '?'} · ${s.poll_count || 0} polls`;
        sel.appendChild(o);
      });
      sel.dataset.loaded = '1';
    } catch (_) { /* optional */ }
  }

  async function refreshConnections() {
    if (!$('goConnBody')) return;
    await loadConnSessions();
    const params = new URLSearchParams();
    params.set('limit', String(connPageSize));
    params.set('offset', String(connPage * connPageSize));
    const ip = ($('goConnIp') || {}).value?.trim();
    const typ = ($('goConnType') || {}).value;
    const pol = ($('goConnPolicy') || {}).value;
    const sess = ($('goConnSession') || {}).value;
    if (ip) params.set('ip', ip);
    if (typ) params.set('type', typ);
    if (pol) params.set('policy', pol);
    if (sess) params.set('session_hex', sess);
    if (($('goConnOffenders') || {}).checked) params.set('offenders', '1');
    try {
      const r = await api('/api/v1/gaming/connections?' + params.toString());
      connTotal = r.total || 0;
      const rows = r.rows || r.items || r.connections || [];
      const body = $('goConnBody');
      if (!rows.length) {
        body.innerHTML = '<tr><td colspan="11" class="sub">No connections match filter</td></tr>';
      } else {
        body.innerHTML = rows.map(row => {
          const ipVal = row.ip || row.remote_ip || '';
          const checked = selectedConn.has(ipVal) ? ' checked' : '';
          return `<tr>
            <td><input type="checkbox" class="go-conn-pick" data-ip="${esc(ipVal)}"${checked}></td>
            <td class="mono">${esc(ipVal)}</td>
            <td>${esc(row.conn_type || row.type || '—')}</td>
            <td>${esc(row.label || '—')}</td>
            <td>${esc(row.intel_summary || row.purpose || row.policy_reason || '—')}</td>
            <td>${row.session_count ?? '—'}</td>
            <td>${row.identical_max ?? '—'}</td>
            <td>${row.tiny_packets ?? '—'}</td>
            <td class="mono">${esc((row.last_seen || row.last_seen_at || '—').toString().slice(0, 19))}</td>
            <td class="mono">${esc((row.session_hex || '—').slice(0, 10))}</td>
            <td>${esc(row.policy || 'none')}</td>
          </tr>`;
        }).join('');
        body.querySelectorAll('.go-conn-pick').forEach(cb => {
          cb.onchange = () => {
            const ipx = cb.dataset.ip;
            if (cb.checked) selectedConn.add(ipx); else selectedConn.delete(ipx);
            setText('goConnSelCount', `${selectedConn.size} selected`);
          };
        });
      }
      const pages = Math.max(1, Math.ceil(connTotal / connPageSize));
      setText('goConnPage', `Page ${connPage + 1} / ${pages} · ${connTotal} total`);
      if ($('goConnPrev')) $('goConnPrev').disabled = connPage <= 0;
      if ($('goConnNext')) $('goConnNext').disabled = (connPage + 1) * connPageSize >= connTotal;
      setText('goConnSelCount', `${selectedConn.size} selected`);

      const off = await api('/api/v1/gaming/connections/offenders?min_sessions=2&limit=20');
      const ob = $('goConnOffendersBody');
      if (ob) {
        const offenders = off.items || off.offenders || [];
        ob.innerHTML = offenders.length ? offenders.map(o => `<tr>
          <td class="mono">${esc(o.ip)}</td>
          <td>${o.session_count ?? '—'}</td>
          <td>${esc(o.conn_types || (o.types || []).join(', ') || '—')}</td>
          <td>${esc(o.label || '—')}</td>
          <td>${o.identical_max ?? '—'}</td>
          <td>${esc(o.policy || 'none')}</td>
        </tr>`).join('') : '<tr><td colspan="6" class="sub">No repeat offenders</td></tr>';
      }
    } catch (e) {
      if ($('goConnBody')) $('goConnBody').innerHTML = `<tr><td colspan="11" class="sub">${esc(e.message)}</td></tr>`;
    }
  }

  async function refreshPeers() {
    if (!$('goPeerBody')) return;
    try {
      const r = await api('/api/v1/gaming/peers');
      const peers = r.peers || r.blocked || r.items || [];
      const body = $('goPeerBody');
      if (!peers.length) {
        body.innerHTML = '<tr><td colspan="6" class="sub">No blocked peers</td></tr>';
        return;
      }
      body.innerHTML = peers.map(p => {
        const ipStr = p.ip || p;
        if (typeof ipStr !== 'string') return '';
        const checked = selectedPeers.has(ipStr) ? ' checked' : '';
        return `<tr>
          <td><input type="checkbox" class="go-peer-pick" data-ip="${esc(ipStr)}"${checked}></td>
          <td class="mono">${esc(ipStr)}</td>
          <td>${esc(p.reason || '—')}</td>
          <td class="mono">${esc((p.expires || p.expires_at || '—').toString().slice(0, 19))}</td>
          <td>${p.hits ?? '—'}</td>
          <td>${p.repeat_offender ? 'repeat' : 'manual'}</td>
        </tr>`;
      }).join('');
      body.querySelectorAll('.go-peer-pick').forEach(cb => {
        cb.onchange = () => {
          const ipx = cb.dataset.ip;
          if (cb.checked) selectedPeers.add(ipx); else selectedPeers.delete(ipx);
          setText('goPeerSelCount', `${selectedPeers.size} selected`);
        };
      });
      setText('goPeerCount', String(peers.length));
      setText('goPeerSelCount', `${selectedPeers.size} selected`);
    } catch (e) {
      setHtml('goPeerBody', `<tr><td colspan="6" class="sub">${esc(e.message)}</td></tr>`);
    }
  }

  async function refreshSubnets() {
    if (!$('goSubnetBody')) return;
    try {
      const r = await api('/api/v1/subnets');
      const rows = r.active || [];
      const body = $('goSubnetBody');
      if (!rows.length) {
        body.innerHTML = '<tr><td colspan="6" class="sub">No blocked subnets</td></tr>';
      } else {
        body.innerHTML = rows.map(s => `<tr>
          <td class="mono">${esc(s.cidr || '—')}</td>
          <td>${esc(s.tier || '—')}</td>
          <td>${esc(s.reason || '—')}</td>
          <td>${esc(s.source || '—')}</td>
          <td>${s.hits ?? '—'}</td>
          <td class="mono">${esc(String(s.expires || '—').slice(0, 19))}</td>
        </tr>`).join('');
      }
      setText('goSubnetCount', `${r.active_count ?? rows.length} active`);
      const cat = r.provider_catalog || {};
      const catParts = Object.entries(cat).map(([k, v]) => `${k}:${v}`).join(' · ');
      setText('goSubnetCatalog', catParts ? `Provider catalog: ${catParts}` : 'Provider catalog: not fetched yet');
    } catch (e) {
      setHtml('goSubnetBody', `<tr><td colspan="6" class="sub">${esc(e.message)}</td></tr>`);
    }
  }

  async function refreshProbeSink() {
    if (!$('goProbeBody')) return;
    try {
      const r = await api('/api/v1/gaming/probe-sink');
      const events = r.recent_events || r.events || r.items || [];
      const body = $('goProbeBody');
      if (!events.length) {
        body.innerHTML = '<tr><td colspan="5" class="sub">No probe sink events</td></tr>';
        return;
      }
      body.innerHTML = events.slice(0, 30).map(ev => `<tr>
        <td class="mono">${esc((ev.ts || ev.time || ev.at || '—').toString().slice(0, 19))}</td>
        <td class="mono">${esc(ev.ip || ev.src_ip || '—')}</td>
        <td>${ev.port ?? ev.dport ?? '—'}</td>
        <td>${esc(ev.proto || 'tcp')}</td>
        <td>${esc(ev.note || ev.action || ev.event || '—')}</td>
      </tr>`).join('');
      setText('goProbeCount', String(r.event_count ?? events.length));
    } catch (e) {
      setText('goProbeCount', '—');
    }
  }

  async function refreshLobbyIntel() {
    if (!$('goIntelStatus')) return;
    try {
      const r = await api('/api/v1/gaming/intel/status');
      setText('goIntelStatus', r.status || (r.ok ? 'ready' : '—'));
      setText('goIntelEntries', r.entry_count != null ? String(r.entry_count) : (r.count != null ? String(r.count) : '—'));
      setText('goIntelLast', r.last_import || r.updated || '—');
    } catch (e) {
      setText('goIntelStatus', 'unavailable');
    }
  }

  async function refreshZones() {
    if (!$('goZonesBody')) return;
    try {
      const r = await fetch('/api/v1/zones');
      const z = await r.json();
      setText('goZonesSummary', z.barrier || '—');
      const byZone = z.devices_by_zone || {};
      const rows = [];
      Object.entries(byZone).forEach(([zone, devs]) => {
        (devs || []).slice(0, 12).forEach(d => {
          rows.push(`<tr><td>${esc(zone)}</td><td class="mono">${esc(d.ip || '—')}</td><td>${esc(d.label || d.mac || '—')}</td></tr>`);
        });
      });
      const body = $('goZonesBody');
      body.innerHTML = rows.length ? rows.join('') : '<tr><td colspan="3" class="sub">No devices classified into zones</td></tr>';
    } catch (e) {
      setText('goZonesSummary', e.message);
    }
  }

  async function refreshPoliciesForm() {
    if (!$('goPolicyJson')) return;
    try {
      const r = await api('/api/v1/policies');
      const pol = r.policies || r;
      $('goPolicyJson').value = JSON.stringify(pol, null, 2);
      const g = pol.gaming || {};
      const ua = g.upload_assist || {};
      const buf = ua.buffer || {};
      if ($('goXboxIp')) $('goXboxIp').value = g.xbox_ip || '';
      if ($('goUploadEnabled')) $('goUploadEnabled').checked = ua.enabled !== false;
      if ($('goCeilFactor')) $('goCeilFactor').value = ua.ceil_factor ?? 0.98;
      if ($('goKickRtt')) $('goKickRtt').value = buf.kick_xbox_rtt || '3ms';
      if ($('goDesyncRtt')) $('goDesyncRtt').value = buf.desync_xbox_rtt || '5ms';
      const mit = g.mitigation || {};
      if ($('goAutoBlockPeers')) $('goAutoBlockPeers').checked = mit.auto_block_peers !== false;
      if ($('goHoneypot')) $('goHoneypot').checked = mit.honeypot_enabled !== false;
    } catch (e) {
      if ($('goPolicyJson')) $('goPolicyJson').value = '/* ' + e.message + ' */';
    }
  }

  async function loadTimelineSessions() {
    const sel = $('goTimelineSession');
    if (!sel || sel.dataset.loaded === '1') return;
    try {
      const r = await api('/api/v1/gaming/connections/sessions?limit=40');
      (r.sessions || []).forEach(s => {
        const o = document.createElement('option');
        o.value = s.session_hex || '';
        o.textContent = `${(s.session_hex || '').slice(0, 12)}… · ${s.phase || '?'} · ${s.conn_count || 0} conns`;
        sel.appendChild(o);
      });
      sel.dataset.loaded = '1';
    } catch (_) { /* optional */ }
  }

  async function refreshTimeline() {
    if (!$('goTimelineBody')) return;
    await loadTimelineSessions();
    const hex = ($('goTimelineSession') || {}).value;
    if (!hex) {
      $('goTimelineBody').innerHTML = '<tr><td colspan="5" class="sub">Select a session</td></tr>';
      return;
    }
    try {
      const r = await api(`/api/v1/gaming/sessions/${encodeURIComponent(hex)}/causal-timeline?limit=120`);
      const events = r.events || [];
      const body = $('goTimelineBody');
      if (!events.length) {
        body.innerHTML = '<tr><td colspan="5" class="sub">No timeline events for this session</td></tr>';
        return;
      }
      body.innerHTML = events.map(ev => `<tr>
        <td class="mono">${esc((ev.ts_iso || '').toString().slice(11, 19) || '—')}</td>
        <td>${esc(ev.kind || '—')}</td>
        <td>${esc(ev.detail || '—')}</td>
        <td class="sub">${esc(ev.causal_label || '—')}</td>
        <td>${esc(ev.phase || '—')}</td>
      </tr>`).join('');
    } catch (e) {
      setHtml('goTimelineBody', `<tr><td colspan="5" class="sub">${esc(e.message)}</td></tr>`);
    }
  }

  async function refreshRoutePref() {
    if (!$('goRouteActive')) return;
    try {
      const r = await api('/api/v1/gaming/route-pref');
      setHtml('goRouteActive', r.active ? badge('ok', 'active') : badge('warn', 'off'));
      const st = r.state || {};
      setText('goRouteGw', st.gw || st.gateway || '—');
    } catch (e) {
      setHtml('goRouteActive', badge('bad', 'error'));
    }
  }

  async function refreshAllowlistLearn() {
    if (!$('goAllowCidrCount')) return;
    try {
      const [r, rqdSt] = await Promise.all([
        api('/api/v1/gaming/allowlist-learn'),
        api('/api/v1/rqd/status').catch(() => ({})),
      ]);
      setText('goAllowCidrCount', String(r.cidr_count ?? '—'));
      const staging = r.staging || {};
      const cands = staging.candidates || [];
      setText('goAllowCandCount', String(cands.length));
      setText('goAllowLearned', String((r.learned_cidrs || []).length));
      const out = $('goAllowOut');
      if (out && !out.dataset.userEdited) {
        out.value = cands.length ? JSON.stringify(cands, null, 2) : '';
      }
      if ($('goRqdEnabled')) {
        setHtml('goRqdEnabled', rqdSt.enabled ? badge('ok', 'on') : badge('warn', 'off'));
        const rs = rqdSt.stats || {};
        setText('goRqdSearches', rs.searches != null ? String(rs.searches) : '—');
        setText('goRqdPruned', rs.quadrants_pruned != null ? String(rs.quadrants_pruned) : '—');
        setText('goRqdCache', rqdSt.shortcut_cache_size != null ? String(rqdSt.shortcut_cache_size) : '—');
      }
    } catch (e) {
      setText('goAllowCidrCount', '—');
    }
  }

  async function refreshInnovation() {
    await Promise.all([refreshTimeline(), refreshRoutePref(), refreshAllowlistLearn(), refreshPatternEncode(), refreshQce()]);
  }

  async function refreshQce() {
    try {
      const st = await api('/api/v1/qce/status');
      if ($('goQceEnabled')) {
        setHtml('goQceEnabled', st.enabled ? badge('ok', 'on') : badge('warn', 'off'));
      }
      const stats = st.stats || {};
      if ($('goQceScore') && stats.avg_consciousness != null && stats.measurements > 0) {
        setText('goQceScore', `${stats.avg_consciousness}`);
      }
    } catch (_) {
      if ($('goQceEnabled')) setText('goQceEnabled', '—');
    }
  }

  async function refreshPatternEncode() {
    try {
      const pe = await api('/api/v1/folding/pattern/status');
      const pes = pe.stats || {};
      if ($('goPatEnabled')) {
        setHtml('goPatEnabled', pe.enabled ? badge('ok', 'on') : badge('warn', 'off'));
      }
      setText('goPatApplyRate', pe.apply_rate_pct != null ? `${pe.apply_rate_pct}%` : '—');
      setText('goPatAvgRatio', pes.avg_ratio != null ? `${pes.avg_ratio}×` : '—');
      setText('goPatRedundancy', pe.pipeline_stage || 'pattern_rle');
    } catch (_) {
      if ($('goPatEnabled')) setText('goPatEnabled', '—');
    }
  }

  async function refreshCutoverStatus() {
    if (!$('goCutoverStatus')) return;
    try {
      const r = await api('/api/v1/cutover/status');
      setHtml('goCutoverStatus', r.cutover
        ? badge('ok', 'LIVE') : badge('warn', r.role || 'staged'));
      setText('goCutoverDetail', `Gateway ${r.gateway_ip || '?'} · DHCP ${r.dhcp?.lease_count ?? '?'} leases · backup ${r.backup_exists ? 'yes' : 'no'}`);
    } catch (_) { setText('goCutoverStatus', '—'); }
  }

  async function refreshSentinelEmbed() {
    const frame = $('goSentinelFrame');
    if (frame && !frame.src) {
      frame.src = `http://${location.hostname}:8098/v1/dashboard`;
    }
  }

  async function refreshAll() {
    await Promise.all([
      refreshUploadAssist(),
      refreshDefenses(),
      refreshConnections(),
      refreshPeers(),
      refreshSubnets(),
      refreshProbeSink(),
      refreshLobbyIntel(),
      refreshZones(),
      refreshPoliciesForm(),
      refreshCutoverStatus(),
      refreshInnovation(),
    ]);
  }

  function bindEvents() {
    const on = (id, fn) => { const el = $(id); if (el) el.onclick = fn; };

    on('goUploadApply', async () => {
      try {
        await api('/api/v1/qos/upload-boost', { method: 'POST', body: JSON.stringify({ action: 'apply' }) });
        toast('Upload boost applied');
        await refreshUploadAssist();
      } catch (e) { showError(e.message); }
    });
    on('goUploadRelax', async () => {
      try {
        await api('/api/v1/qos/upload-boost', { method: 'POST', body: JSON.stringify({ action: 'relax' }) });
        toast('Upload boost relaxed');
        await refreshUploadAssist();
      } catch (e) { showError(e.message); }
    });
    on('goBufferKick', async () => {
      try {
        await api('/api/v1/qos/buffer', { method: 'POST', body: JSON.stringify({ profile: 'kick' }) });
        toast('Kick buffer profile (3ms) applied');
        await refreshDefenses();
      } catch (e) { showError(e.message); }
    });
    on('goBufferDesync', async () => {
      try {
        await api('/api/v1/qos/buffer', { method: 'POST', body: JSON.stringify({ profile: 'desync' }) });
        toast('Desync buffer profile (5ms) applied');
        await refreshDefenses();
      } catch (e) { showError(e.message); }
    });
    on('goBufferOff', async () => {
      try {
        await api('/api/v1/qos/buffer', { method: 'POST', body: JSON.stringify({ action: 'off' }) });
        toast('Buffers restored to idle baseline');
        await refreshDefenses();
      } catch (e) { showError(e.message); }
    });

    on('goShieldApply', async () => {
      const level = ($('goShieldLevel') || {}).value || 'normal';
      const peers = ($('goShieldPeers') || {}).value.split(/[\s,]+/).filter(Boolean);
      try {
        let r;
        if (level === 'console') {
          r = await api('/api/v1/gaming/console-mode', { method: 'POST', body: JSON.stringify({ enabled: true, peer_ips: peers }) });
        } else if (level === 'in-match') {
          r = await api('/api/v1/shield/enable', { method: 'POST', body: JSON.stringify({ level: 'in-match', ips: peers }) });
        } else {
          r = await api('/api/v1/shield/enable', { method: 'POST', body: JSON.stringify({ level, ips: peers }) });
        }
        if (r.ok === false) throw new Error(r.error || 'shield failed');
        toast(`Shield: ${level}`);
      } catch (e) { showError(e.message); }
    });
    on('goShieldRelax', async () => {
      try {
        await api('/api/v1/shield/relax', { method: 'POST', body: '{}' });
        toast('Shield relaxed');
      } catch (e) { showError(e.message); }
    });

    on('goConnRefresh', () => refreshConnections());
    on('goConnPrev', () => { if (connPage > 0) { connPage--; refreshConnections(); } });
    on('goConnNext', () => { connPage++; refreshConnections(); });
    ['goConnIp', 'goConnType', 'goConnPolicy', 'goConnSession', 'goConnOffenders'].forEach(id => {
      const el = $(id);
      if (!el) return;
      el.onchange = () => { connPage = 0; refreshConnections(); };
      if (el.tagName === 'INPUT') el.oninput = () => { connPage = 0; refreshConnections(); };
    });
    if ($('goConnPageSize')) $('goConnPageSize').onchange = () => {
      connPageSize = parseInt($('goConnPageSize').value, 10) || 25;
      connPage = 0;
      refreshConnections();
    };

    async function connAction(action) {
      const ips = [...selectedConn];
      if (!ips.length) { showError('Select connection rows first'); return; }
      await api('/api/v1/gaming/connections/action', { method: 'POST', body: JSON.stringify({ ips, action }) });
      toast(`Connections: ${action}`);
      selectedConn.clear();
      await refreshConnections();
    }
    on('goConnProtect', () => connAction('protect'));
    on('goConnBlock', () => connAction('block'));
    on('goConnNoProtect', () => connAction('none'));
    on('goConnRemove', async () => {
      const ips = [...selectedConn];
      if (!ips.length) return;
      await api('/api/v1/gaming/connections/action', { method: 'POST', body: JSON.stringify({ ips, action: 'remove' }) });
      selectedConn.clear();
      await refreshConnections();
    });
    on('goConnInvestigate', async () => {
      try {
        const r = await api('/api/v1/gaming/investigate/run', { method: 'POST', body: JSON.stringify({ limit: 25 }) });
        toast(`Investigated ${r.updated ?? r.count ?? '?'} unknowns`);
        await refreshConnections();
      } catch (e) { showError(e.message); }
    });

    on('goPeerRefresh', () => refreshPeers());
    on('goPeerBlock', async () => {
      const manual = ($('goPeerIp') || {}).value.trim();
      const ips = manual ? [manual] : [...selectedPeers];
      if (!ips.length) { showError('Enter IP or select peers'); return; }
      await api('/api/v1/gaming/peers/block', { method: 'POST', body: JSON.stringify({ ips, reason: 'dashboard', ttl_sec: 86400 }) });
      toast(`Blocked ${ips.length} peer(s)`);
      selectedPeers.clear();
      if ($('goPeerIp')) $('goPeerIp').value = '';
      await refreshPeers();
    });
    on('goPeerRemove', async () => {
      const ips = [...selectedPeers];
      if (!ips.length) return;
      await api('/api/v1/gaming/peers/remove', { method: 'POST', body: JSON.stringify({ ips }) });
      selectedPeers.clear();
      await refreshPeers();
    });
    on('goPeerSyncShield', async () => {
      const ips = [...selectedPeers];
      const level = ($('goShieldLevel') || {}).value || 'peer-strict';
      await api('/api/v1/gaming/peers/sync-shield', { method: 'POST', body: JSON.stringify({ level, ips }) });
      toast('Shield synced with peer list');
    });
    on('goPeerDecay', async () => {
      await api('/api/v1/gaming/peers/decay', { method: 'POST', body: '{}' });
      toast('Expired peers decayed');
      await refreshPeers();
    });

    on('goSubnetRefresh', () => refreshSubnets());
    on('goSubnetBlock', async () => {
      const ip = ($('goSubnetIp') || {}).value.trim();
      const cidr = ($('goSubnetCidr') || {}).value.trim();
      const body = { reason: 'dashboard' };
      if (cidr) body.cidrs = [cidr];
      else if (ip) body.ips = [ip];
      else { showError('Enter IP or CIDR'); return; }
      await api('/api/v1/subnets/block', { method: 'POST', body: JSON.stringify(body) });
      toast('Subnet block queued');
      if ($('goSubnetIp')) $('goSubnetIp').value = '';
      if ($('goSubnetCidr')) $('goSubnetCidr').value = '';
      await refreshSubnets();
    });
    on('goSubnetApply', async () => {
      await api('/api/v1/subnets/apply', { method: 'POST', body: '{}' });
      toast('Subnet nft rules re-applied');
      await refreshSubnets();
    });
    on('goSubnetProviders', async () => {
      try {
        const r = await api('/api/v1/subnets/refresh-providers', { method: 'POST', body: '{}' });
        toast(`Provider catalog updated (${r.cidr_count ?? '?'} CIDRs)`);
        await refreshSubnets();
      } catch (e) { showError(e.message); }
    });

    on('goProbeRefresh', () => refreshProbeSink());
    on('goAbuseGen', async () => {
      const ip = ($('goAbuseIp') || {}).value.trim();
      if (!ip) { showError('Enter IP for abuse report'); return; }
      try {
        const r = await api('/api/v1/gaming/abuse-reports/generate', { method: 'POST', body: JSON.stringify({ ip }) });
        if ($('goAbuseOut')) $('goAbuseOut').value = r.report || r.body || JSON.stringify(r, null, 2);
        toast('Abuse report generated');
      } catch (e) { showError(e.message); }
    });

    on('goIntelExport', async () => {
      try {
        const r = await api('/api/v1/gaming/intel/export');
        if ($('goIntelOut')) $('goIntelOut').value = JSON.stringify(r, null, 2);
        toast('Intel exported');
      } catch (e) { showError(e.message); }
    });
    on('goIntelImport', async () => {
      try {
        const raw = ($('goIntelOut') || {}).value.trim();
        const body = JSON.parse(raw);
        await api('/api/v1/gaming/intel/import', { method: 'POST', body: JSON.stringify(body) });
        toast('Intel imported');
        await refreshLobbyIntel();
      } catch (e) { showError(e.message); }
    });

    on('goPolicyLoad', () => refreshPoliciesForm());
    on('goPolicySaveQuick', async () => {
      try {
        const cur = (await api('/api/v1/policies')).policies || {};
        cur.gaming = cur.gaming || {};
        cur.gaming.xbox_ip = $('goXboxIp').value.trim() || cur.gaming.xbox_ip;
        cur.gaming.upload_assist = cur.gaming.upload_assist || {};
        cur.gaming.upload_assist.enabled = $('goUploadEnabled').checked;
        cur.gaming.upload_assist.ceil_factor = parseFloat($('goCeilFactor').value) || 0.98;
        cur.gaming.upload_assist.buffer = cur.gaming.upload_assist.buffer || {};
        cur.gaming.upload_assist.buffer.kick_xbox_rtt = $('goKickRtt').value.trim();
        cur.gaming.upload_assist.buffer.desync_xbox_rtt = $('goDesyncRtt').value.trim();
        cur.gaming.mitigation = cur.gaming.mitigation || {};
        cur.gaming.mitigation.auto_block_peers = $('goAutoBlockPeers').checked;
        cur.gaming.mitigation.honeypot_enabled = $('goHoneypot').checked;
        await api('/api/v1/policies', { method: 'POST', body: JSON.stringify(cur) });
        toast('Gaming policies saved');
        await refreshPoliciesForm();
      } catch (e) { showError(e.message); }
    });
    on('goPolicySaveJson', async () => {
      try {
        const body = JSON.parse($('goPolicyJson').value);
        await api('/api/v1/policies', { method: 'POST', body: JSON.stringify(body) });
        toast('Full policies saved');
        await refreshPoliciesForm();
      } catch (e) { showError(e.message); }
    });

    on('goProbeHostnames', async () => {
      try {
        const r = await api('/api/v1/devices/probe-hostnames', { method: 'POST', body: '{}' });
        toast(`Probed ${r.probed ?? r.count ?? '?'} devices`);
      } catch (e) { showError(e.message); }
    });

    on('goSentinelReload', () => {
      const f = $('goSentinelFrame');
      if (f) f.src = f.src;
    });

    on('goTimelineRefresh', () => refreshTimeline());
    on('goRouteApply', async () => {
      try {
        const gw = ($('goRouteGwIn') || {}).value?.trim();
        const body = gw ? { gateway: gw } : { action: 'apply' };
        await api('/api/v1/gaming/route-pref', { method: 'POST', body: JSON.stringify(body) });
        toast('Route preference applied');
        await refreshRoutePref();
      } catch (e) { showError(e.message); }
    });
    on('goRouteClear', async () => {
      try {
        await api('/api/v1/gaming/route-pref', { method: 'POST', body: JSON.stringify({ action: 'clear' }) });
        toast('Route preference cleared');
        await refreshRoutePref();
      } catch (e) { showError(e.message); }
    });
    on('goAllowAnalyze', async () => {
      try {
        const hex = ($('goTimelineSession') || {}).value || ($('goConnSession') || {}).value || null;
        const r = await api('/api/v1/gaming/allowlist-learn/analyze', {
          method: 'POST',
          body: JSON.stringify({ session_hex: hex }),
        });
        const out = $('goAllowOut');
        if (out) {
          out.dataset.userEdited = '';
          out.value = JSON.stringify(r.candidates || [], null, 2);
        }
        toast(`Found ${(r.candidates || []).length} candidate CIDR(s)`);
        await refreshAllowlistLearn();
      } catch (e) { showError(e.message); }
    });
    on('goAllowApply', async () => {
      try {
        const reload = ($('goAllowReloadShield') || {}).checked;
        const r = await api('/api/v1/gaming/allowlist-learn/apply', {
          method: 'POST',
          body: JSON.stringify({ reload_shield: reload }),
        });
        toast(`Merged ${(r.added || []).length} CIDR(s)`);
        await refreshAllowlistLearn();
      } catch (e) { showError(e.message); }
    });
    const allowOut = $('goAllowOut');
    if (allowOut) {
      allowOut.oninput = () => { allowOut.dataset.userEdited = '1'; };
    }

    on('goRqdBufferRec', async () => {
      try {
        const r = await api('/api/v1/rqd/buffer-profile');
        setText('goRqdBufferOut', `profile=${r.profile} score=${r.score} pruned=${(r.rqd || {}).pruned ?? '?'}`);
        toast(`RQD recommends: ${r.profile}`);
      } catch (e) { showError(e.message); }
    });
    on('goRqdBufferApply', async () => {
      try {
        const r = await api('/api/v1/rqd/buffer-profile', { method: 'POST', body: JSON.stringify({ apply: true }) });
        setText('goRqdBufferOut', `applied profile=${r.profile}`);
        toast(`RQD buffer: ${r.profile}`);
        await refreshDefenses();
        await refreshAllowlistLearn();
      } catch (e) { showError(e.message); }
    });

    on('goAsviScan', async () => {
      try {
        const hex = ($('goTimelineSession') || {}).value || ($('goConnSession') || {}).value || null;
        const r = await api('/api/v1/asvi/scan', { method: 'POST', body: JSON.stringify({ session_hex: hex, limit: 300 }) });
        setText('goAsviVoidCount', String(r.void_count ?? '—'));
        setText('goAsviMax', r.max_asvi != null ? String(r.max_asvi) : '—');
        const sm = r.smst_summary || {};
        setText('goAsviAct', sm.act != null ? String(sm.act) : '—');
        setText('goAsviStage', sm.stage != null ? String(sm.stage) : '—');
        if ($('goAsviOut')) $('goAsviOut').value = JSON.stringify(r.voids || [], null, 2);
        toast(`ASVI: ${r.void_count ?? 0} void(s)`);
      } catch (e) { showError(e.message); }
    });
    on('goAsviUnknown', async () => {
      try {
        const r = await api('/api/v1/asvi/unknown-voids?limit=200');
        if ($('goAsviOut')) $('goAsviOut').value = JSON.stringify(r.voids || [], null, 2);
        setText('goAsviVoidCount', String(r.void_count ?? '—'));
        toast(`Unknown voids: ${r.void_count ?? 0}`);
      } catch (e) { showError(e.message); }
    });

    const patternSample = () => JSON.stringify({
      probe: true,
      ts: Date.now(),
      connections: Array.from({ length: 40 }, (_, i) => ({ ip: `203.0.113.${i}`, hit_count: i + 1 })),
    });
    on('goPatAnalyze', async () => {
      try {
        const r = await api('/api/v1/folding/pattern/encode', {
          method: 'POST',
          body: JSON.stringify({ payload: patternSample(), analyze_only: true }),
        });
        if ($('goPatOut')) $('goPatOut').value = JSON.stringify(r.analysis || r, null, 2);
        const a = r.analysis || {};
        setText('goPatRedundancy', a.structural_redundancy_pct != null ? `${a.structural_redundancy_pct}%` : '—');
        toast(`Pattern redundancy ${a.structural_redundancy_pct ?? '?'}%`);
      } catch (e) { showError(e.message); }
    });
    on('goPatEncode', async () => {
      try {
        const r = await api('/api/v1/folding/pattern/encode', {
          method: 'POST',
          body: JSON.stringify({ payload: patternSample() }),
        });
        if ($('goPatOut')) $('goPatOut').value = JSON.stringify(r, null, 2);
        setText('goPatAvgRatio', r.ratio != null ? `${r.ratio}×` : '—');
        toast(r.applied ? `Pattern encode ${r.ratio}× (lossless=${r.lossless_ok})` : 'Pattern stage skipped (no gain)');
        await refreshPatternEncode();
      } catch (e) { showError(e.message); }
    });

    on('goQceMeasure', async () => {
      try {
        const hex = ($('goTimelineSession') || {}).value || ($('goConnSession') || {}).value || null;
        const r = await api('/api/v1/qce/measure', { method: 'POST', body: JSON.stringify({ session_hex: hex, limit: 300 }) });
        if ($('goQceOut')) $('goQceOut').value = JSON.stringify(r, null, 2);
        setText('goQceEntropy', r.entanglement_entropy != null ? `${r.entanglement_entropy} bits` : '—');
        setText('goQceScore', r.consciousness_score != null ? String(r.consciousness_score) : '—');
        setHtml('goQcePeak', r.peak_entropy_band ? badge('ok', 'yes') : badge('warn', 'no'));
        toast(`QCE S=${r.entanglement_entropy ?? '?'} · score=${r.consciousness_score ?? '?'}`);
        await refreshQce();
      } catch (e) { showError(e.message); }
    });
    on('goQceTelemetry', async () => {
      try {
        const r = await api('/api/v1/qce/measure', { method: 'POST', body: JSON.stringify({ device: ($('goXboxIp') || {}).value || null }) });
        if ($('goQceOut')) $('goQceOut').value = JSON.stringify(r, null, 2);
        setText('goQceEntropy', r.entanglement_entropy != null ? `${r.entanglement_entropy} bits` : '—');
        setText('goQceScore', r.consciousness_score != null ? String(r.consciousness_score) : '—');
        toast(`Telemetry QCE: ${r.consciousness_score ?? '?'}/100`);
      } catch (e) { showError(e.message); }
    });
  }

  global.ArrayFwGamingOps = {
    init(deps) {
      api = deps.api;
      $ = deps.$;
      showError = deps.showError;
      toast = deps.toast || ((msg) => { showError(msg); setTimeout(() => showError(''), 2500); });
      bindEvents();
    },
    refreshAll,
    refreshUploadAssist,
    refreshDefenses,
    refreshConnections,
    refreshPeers,
    refreshSubnets,
    refreshCutoverStatus,
    refreshSentinelEmbed,
    refreshInnovation,
    refreshTimeline,
    refreshRoutePref,
    refreshAllowlistLearn,
    refreshPatternEncode,
    refreshQce,
  };
})(window);
