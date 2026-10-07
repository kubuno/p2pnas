// Instance administration of p2pnas, rendered in the core admin console under
// Modules ▸ p2pnas. Everything here used to live in a per-user "Settings" page,
// but none of it was ever a real user preference: contribution, quotas, peers,
// repair and metrics are all node-wide administrator actions. In the admin
// console the connected user IS an admin, so the old isAdmin probing is gone —
// each section simply loads its own data.
import { useEffect, useState, Fragment } from 'react'
import {
  HardDrive, Users, Save, Plus, ShieldCheck, RefreshCw, Trash2, Activity,
  AlertTriangle, Wifi, WifiOff, Gauge, Radar, ShieldAlert, FileSearch, MapPin,
} from 'lucide-react'
import { useConfirm, ModuleServiceRegistry, ModuleAdminRegistry } from '@kubuno/sdk'
import { ConfirmDialog } from '@ui'
import {
  p2pnasApi, formatBytes, timeAgo,
  type NodeStatus, type QuotaRow, type PeerRow, type RepairReport, type EventRow,
  type NodeMetrics, type FileHealth, type FileRow, type FilePlacement,
} from '../api'
import {
  Stat, DiscoveryBadge, HealthBadge, PlacementMap, LatencyBadge, ReliabilityBadge,
  QuotaEditor, Feedback, toBytes, toGib, errMsg, isLive, eventLabel,
  type PeerMarker,
} from './parts'

// ── overview: node storage stats (block 1, stats) ─────────────────────────────

function NodeStatusStats() {
  const [status, setStatus] = useState<NodeStatus | null>(null)
  useEffect(() => { void p2pnasApi.status().then(setStatus).catch(() => {}) }, [])
  return (
    <section data-module="p2pnas" className="bg-surface-0 rounded-lg border border-border p-5">
      <div className="flex items-center gap-2 mb-3">
        <HardDrive className="w-5 h-5 text-primary" />
        <h2 className="font-semibold text-text-primary">Nœud de stockage</h2>
      </div>
      {status ? (
        <div className="grid grid-cols-3 gap-4 text-sm">
          <Stat label="Contribué" value={formatBytes(status.node.contributed_bytes)} />
          <Stat label="Utilisé" value={formatBytes(status.node.used_bytes)} />
          <Stat label="Disponible" value={formatBytes(status.node.available_bytes)} />
        </div>
      ) : (
        <p className="text-sm text-text-tertiary">Chargement…</p>
      )}
    </section>
  )
}

// ── overview: node metrics + discovery state (block 3) ────────────────────────

function NodeMetricsSection() {
  const [metrics, setMetrics] = useState<NodeMetrics | null>(null)
  useEffect(() => { void p2pnasApi.metrics().then(setMetrics).catch(() => {}) }, [])
  if (!metrics) {
    return (
      <section data-module="p2pnas" className="bg-surface-0 rounded-lg border border-border p-5">
        <div className="flex items-center gap-2 mb-3">
          <Gauge className="w-5 h-5 text-primary" />
          <h2 className="font-semibold text-text-primary">Métriques du nœud</h2>
        </div>
        <p className="text-sm text-text-tertiary">Chargement…</p>
      </section>
    )
  }
  return (
    <section data-module="p2pnas" className="bg-surface-0 rounded-lg border border-border p-5">
      <div className="flex items-center gap-2 mb-3">
        <Gauge className="w-5 h-5 text-primary" />
        <h2 className="font-semibold text-text-primary">Métriques du nœud</h2>
      </div>
      <div className="grid grid-cols-3 sm:grid-cols-4 gap-2 text-sm">
        <Stat label="Fichiers" value={String(metrics.storage.files)} />
        <Stat label="Chunks" value={String(metrics.storage.chunks)} />
        <Stat label="Stockés (données)" value={formatBytes(metrics.storage.stored_bytes)} />
        <Stat label="Hébergés pour autrui" value={`${metrics.storage.hosted_shards} (${formatBytes(metrics.node.hosted_bytes)})`} />
        <Stat label="Pairs actifs" value={String(metrics.peers.active)} />
        <Stat label="Pairs hors-ligne" value={String(metrics.peers.down)} danger={metrics.peers.down > 0} />
        <Stat label="Jobs en file" value={String(metrics.jobs.pending + metrics.jobs.running)} />
        <Stat label="Alertes perte" value={String(metrics.risk.unrepairable_events)} danger={metrics.risk.unrepairable_events > 0} />
      </div>
      <div className="flex items-center gap-2 mt-3 text-sm">
        <Radar className="w-4 h-4 text-text-tertiary" />
        <span className="text-text-secondary">Découverte :</span>
        <DiscoveryBadge label="mDNS (LAN)" on={metrics.discovery.mdns} />
        <DiscoveryBadge label="DHT (Internet)" on={metrics.discovery.dht} />
      </div>
    </section>
  )
}

// ── overview: event log (block 8) ─────────────────────────────────────────────

function EventLog() {
  const [events, setEvents] = useState<EventRow[]>([])
  useEffect(() => { void p2pnasApi.listEvents().then(setEvents).catch(() => {}) }, [])
  return (
    <section data-module="p2pnas" className="bg-surface-0 rounded-lg border border-border p-5">
      <div className="flex items-center gap-2 mb-3">
        <Activity className="w-5 h-5 text-primary" />
        <h2 className="font-semibold text-text-primary">Journal d’événements</h2>
      </div>
      {events.length === 0 ? (
        <p className="text-sm text-text-tertiary">Aucun événement enregistré.</p>
      ) : (
        <ul className="space-y-1.5 text-sm">
          {events.map(ev => (
            <li key={ev.id} className="flex items-start gap-2">
              {ev.kind === 'chunk_unrepairable'
                ? <AlertTriangle className="w-4 h-4 text-amber-500 mt-0.5 shrink-0" />
                : <Activity className="w-4 h-4 text-text-tertiary mt-0.5 shrink-0" />}
              <div className="min-w-0">
                <span className="text-text-primary">{eventLabel(ev)}</span>
                <span className="text-text-tertiary text-xs ml-2">{timeAgo(ev.created_at)}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

// ── quotas: network contribution form (block 1, form) ─────────────────────────

function ContributionForm() {
  const [status, setStatus] = useState<NodeStatus | null>(null)
  const [contrib, setContrib] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  async function load() {
    const s = await p2pnasApi.status()
    setStatus(s)
    setContrib(toGib(s.node.contributed_bytes))
  }
  useEffect(() => { void load().catch(() => {}) }, [])

  async function save() {
    setErr(null); setMsg(null)
    try {
      await p2pnasApi.setContribution(toBytes(contrib))
      setMsg('Contribution mise à jour')
      await load()
    } catch (e) {
      setErr(errMsg(e, 'Échec'))
    }
  }

  return (
    <section data-module="p2pnas" className="bg-surface-0 rounded-lg border border-border p-5">
      <div className="flex items-center gap-2 mb-3">
        <HardDrive className="w-5 h-5 text-primary" />
        <h2 className="font-semibold text-text-primary">Contribution au réseau</h2>
      </div>
      <Feedback msg={msg} err={err} />
      {status && (
        <div className="grid grid-cols-3 gap-4 text-sm mb-4">
          <Stat label="Contribué" value={formatBytes(status.node.contributed_bytes)} />
          <Stat label="Utilisé" value={formatBytes(status.node.used_bytes)} />
          <Stat label="Disponible" value={formatBytes(status.node.available_bytes)} />
        </div>
      )}
      <div className="flex items-end gap-2">
        <label className="text-sm">
          <div className="text-text-secondary mb-1">Espace contribué au réseau (Go)</div>
          <input
            value={contrib}
            onChange={e => setContrib(e.target.value)}
            type="number" min="0" step="0.1"
            className="w-40 px-2.5 py-1.5 rounded border border-border bg-surface-0 text-text-primary"
          />
        </label>
        <button
          onClick={save}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-white text-sm hover:bg-primary-hover"
        >
          <Save className="w-4 h-4" /> Enregistrer
        </button>
      </div>
    </section>
  )
}

// ── quotas: per-user quotas (block 7) ─────────────────────────────────────────

function UserQuotas() {
  const [quotas, setQuotas] = useState<QuotaRow[]>([])
  const [newUser, setNewUser] = useState('')
  const [newQuota, setNewQuota] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  async function load() { setQuotas(await p2pnasApi.listQuotas()) }
  useEffect(() => { void load().catch(() => {}) }, [])

  async function run(fn: () => Promise<unknown>, ok: string) {
    setErr(null); setMsg(null)
    try { await fn(); setMsg(ok); await load() } catch (e) { setErr(errMsg(e, 'Échec')) }
  }

  return (
    <section data-module="p2pnas" className="bg-surface-0 rounded-lg border border-border p-5">
      <h2 className="font-semibold text-text-primary mb-3">Quotas par utilisateur</h2>
      <Feedback msg={msg} err={err} />
      <div className="space-y-2">
        {quotas.map(q => (
          <QuotaEditor key={q.user_id} row={q} onSave={(gib) => run(() => p2pnasApi.setQuota(q.user_id, toBytes(gib)), 'Quota mis à jour')} />
        ))}
        {quotas.length === 0 && <p className="text-sm text-text-tertiary">Aucun quota alloué.</p>}
      </div>
      <div className="mt-4 pt-4 border-t border-border flex items-end gap-2">
        <label className="text-sm flex-1">
          <div className="text-text-secondary mb-1">Identifiant utilisateur (UUID)</div>
          <input value={newUser} onChange={e => setNewUser(e.target.value)} placeholder="00000000-0000-…"
            className="w-full px-2.5 py-1.5 rounded border border-border bg-surface-0 text-text-primary font-mono text-xs" />
        </label>
        <label className="text-sm">
          <div className="text-text-secondary mb-1">Quota (Go)</div>
          <input value={newQuota} onChange={e => setNewQuota(e.target.value)} type="number" min="0" step="0.1"
            className="w-28 px-2.5 py-1.5 rounded border border-border bg-surface-0 text-text-primary" />
        </label>
        <button
          onClick={() => run(() => p2pnasApi.setQuota(newUser.trim(), toBytes(newQuota)), 'Quota alloué').then(() => { setNewUser(''); setNewQuota('') })}
          disabled={!newUser.trim()}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-white text-sm hover:bg-primary-hover disabled:opacity-50"
        >
          <Plus className="w-4 h-4" /> Allouer
        </button>
      </div>
    </section>
  )
}

// ── peers: trusted peers table (block 5) ──────────────────────────────────────

function TrustedPeers() {
  const [peers, setPeers] = useState<PeerRow[]>([])
  const [newPeer, setNewPeer] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const { confirm, confirmState, handleConfirm, handleCancel } = useConfirm()

  async function load() { setPeers(await p2pnasApi.listPeers()) }
  useEffect(() => { void load().catch(() => {}) }, [])

  async function run(fn: () => Promise<unknown>, ok: string) {
    setErr(null); setMsg(null)
    try { await fn(); setMsg(ok); await load() } catch (e) { setErr(errMsg(e, 'Échec')) }
  }

  async function removePeer(p: PeerRow) {
    const ok = await confirm({
      title: 'Oublier ce pair ?',
      message: `Les fragments hébergés chez ${p.peer_id.slice(0, 12)}… seront considérés comme perdus et re-répliqués à la prochaine réparation.`,
      variant: 'danger',
      confirmLabel: 'Oublier',
    })
    if (ok) await run(() => p2pnasApi.removePeer(p.peer_id), 'Pair oublié')
  }

  return (
    <section data-module="p2pnas" className="bg-surface-0 rounded-lg border border-border p-5">
      <div className="flex items-center gap-2 mb-3">
        <Users className="w-5 h-5 text-primary" />
        <h2 className="font-semibold text-text-primary">Pairs de confiance</h2>
        <span className="text-xs text-text-tertiary ml-1">
          ({peers.filter(isLive).length} en ligne / {peers.length})
        </span>
      </div>
      <Feedback msg={msg} err={err} />
      {peers.length === 0 ? (
        <p className="text-sm text-text-tertiary mb-3">
          Aucun pair. Ajoutez l’adresse <code>ip:port</code> du listener P2P d’une connaissance pour
          répartir vos fragments et gagner en résilience.
        </p>
      ) : (
        <table className="w-full text-sm mb-3">
          <thead><tr className="text-left text-xs text-text-tertiary border-b border-border">
            <th className="py-1.5 font-medium">Pair</th><th className="py-1.5 font-medium">Adresse</th>
            <th className="py-1.5 font-medium">État</th>
            <th className="py-1.5 font-medium">Latence</th>
            <th className="py-1.5 font-medium">Fiabilité</th><th className="py-1.5 font-medium">Vu</th>
            <th className="py-1.5 font-medium"></th>
          </tr></thead>
          <tbody>
            {peers.map(p => {
              const live = isLive(p)
              return (
                <tr key={p.peer_id} className="border-b border-border/60">
                  <td className="py-1.5 font-mono text-xs" title={p.peer_id}>{p.peer_id.slice(0, 12)}…</td>
                  <td className="py-1.5">{p.addr}</td>
                  <td className="py-1.5">
                    {live
                      ? <span className="inline-flex items-center gap-1 text-green-600"><Wifi className="w-3.5 h-3.5" /> en ligne</span>
                      : <span className="inline-flex items-center gap-1 text-text-tertiary"><WifiOff className="w-3.5 h-3.5" /> hors ligne</span>}
                  </td>
                  <td className="py-1.5 text-xs">{p.rtt_ms != null ? <LatencyBadge ms={p.rtt_ms} /> : <span className="text-text-tertiary">—</span>}</td>
                  <td className="py-1.5"><ReliabilityBadge score={p.reliability_score} /></td>
                  <td className="py-1.5 text-text-tertiary text-xs">{timeAgo(p.last_seen)}</td>
                  <td className="py-1.5 text-right">
                    <button onClick={() => removePeer(p)} title="Oublier ce pair"
                      className="p-1 rounded hover:bg-surface-2 text-text-tertiary hover:text-red-600">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
      <div className="flex items-end gap-2 pt-1">
        <label className="text-sm flex-1">
          <div className="text-text-secondary mb-1">Adresse du pair (ip:port)</div>
          <input value={newPeer} onChange={e => setNewPeer(e.target.value)} placeholder="203.0.113.5:7474"
            className="w-full px-2.5 py-1.5 rounded border border-border bg-surface-0 text-text-primary font-mono text-xs" />
        </label>
        <button
          onClick={() => run(() => p2pnasApi.addPeer(newPeer.trim()), 'Pair ajouté').then(() => setNewPeer(''))}
          disabled={!newPeer.trim()}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-white text-sm hover:bg-primary-hover disabled:opacity-50"
        >
          <Plus className="w-4 h-4" /> Ajouter
        </button>
      </div>
      {confirmState && <ConfirmDialog {...confirmState} onConfirm={handleConfirm} onCancel={handleCancel} />}
    </section>
  )
}

// ── peers: geographic map of peers (block 6, rendered by the maps module) ──────

function PeerMap() {
  // Geo features (peer country / jurisdiction / map) are provided by the maps
  // module. These are undefined when maps isn't installed/active → degrade.
  const geoAvailable = !!ModuleServiceRegistry.get('maps', 'geoip')
  const MapsMiniMap = ModuleServiceRegistry.get<React.FC<{ markers: PeerMarker[]; height?: number }>>('maps', 'MiniMap')
  const [peers, setPeers] = useState<PeerRow[]>([])
  const [metrics, setMetrics] = useState<NodeMetrics | null>(null)
  const [peerMap, setPeerMap] = useState<PeerMarker[] | null>(null)
  const [mapBusy, setMapBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    if (!geoAvailable) return
    void p2pnasApi.listPeers().then(setPeers).catch(() => {})
    void p2pnasApi.metrics().then(setMetrics).catch(() => {})
  }, [geoAvailable])

  async function showPeerMap() {
    const geoip = ModuleServiceRegistry.get<(ip: string) => Promise<{ lat?: number | null; lng?: number | null }>>('maps', 'geoip')
    if (!geoip) return
    setMapBusy(true)
    try {
      const out: PeerMarker[] = []
      // This node (from its discovered public IP).
      const selfIp = metrics?.node && (metrics.node as { public_ip?: string | null }).public_ip
      if (selfIp) {
        const g = await geoip(selfIp)
        if (g.lat != null && g.lng != null) out.push({ lat: g.lat, lng: g.lng, label: 'Ce nœud', color: '#1a73e8' })
      }
      for (const p of peers) {
        const ip = p.addr.split(':')[0]
        const g = await geoip(ip)
        if (g.lat != null && g.lng != null) {
          out.push({ lat: g.lat, lng: g.lng, label: `${p.peer_id.slice(0, 10)}… (${p.addr})`, color: p.rtt_ms != null && p.rtt_ms < 150 ? '#1e8e3e' : '#d93025' })
        }
      }
      setPeerMap(out)
    } catch (e) {
      setErr(errMsg(e, 'Carte indisponible'))
    } finally {
      setMapBusy(false)
    }
  }

  // Auto-load the peers map once maps + peer data are ready.
  useEffect(() => {
    if (geoAvailable && MapsMiniMap && peerMap === null && !mapBusy && (peers.length > 0 || !!metrics)) {
      void showPeerMap()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [geoAvailable, peers.length, metrics])

  // Degrade silently: without the maps module there is no map to render.
  if (!geoAvailable || !MapsMiniMap) {
    return (
      <section data-module="p2pnas" className="bg-surface-0 rounded-lg border border-border p-5">
        <div className="flex items-center gap-2 mb-3">
          <Radar className="w-5 h-5 text-primary" />
          <h2 className="font-semibold text-text-primary">Carte des pairs</h2>
        </div>
        <div className="flex items-start gap-2 rounded-md bg-amber-50 border border-amber-200 px-3 py-2 text-xs text-amber-700">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
          <span>
            La localisation géographique des pairs (pays, carte) nécessite le module <strong>maps</strong>,
            qui n’est pas activé. La carte reste indisponible tant que maps n’est pas installé.
          </span>
        </div>
      </section>
    )
  }

  return (
    <section data-module="p2pnas" className="bg-surface-0 rounded-lg border border-border p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Radar className="w-5 h-5 text-primary" />
          <h2 className="font-semibold text-text-primary">Carte des pairs</h2>
        </div>
        <button
          onClick={showPeerMap}
          disabled={mapBusy}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-border text-sm hover:bg-surface-2 text-text-secondary disabled:opacity-50"
        >
          <Radar className={`w-4 h-4 ${mapBusy ? 'animate-spin' : ''}`} />
          {mapBusy ? 'Localisation…' : peerMap ? 'Actualiser' : 'Afficher la carte'}
        </button>
      </div>
      <Feedback err={err} />
      {peerMap && peerMap.length === 0 && (
        <p className="text-sm text-text-tertiary">Aucun pair géolocalisable (IP privées / non résolues).</p>
      )}
      {peerMap && peerMap.length > 0 && <MapsMiniMap markers={peerMap} height={320} />}
      {!peerMap && (
        <p className="text-sm text-text-tertiary">
          Affiche ce nœud et ses pairs sur une carte, par localisation GeoIP (rendue par le module maps).
        </p>
      )}
    </section>
  )
}

// ── maintenance: resilience & repair actions (block 2) ────────────────────────

function RepairActions() {
  const [status, setStatus] = useState<NodeStatus | null>(null)
  const [repair, setRepair] = useState<RepairReport | null>(null)
  const [repairing, setRepairing] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => { void p2pnasApi.status().then(setStatus).catch(() => {}) }, [])

  async function rebalance() {
    setErr(null); setMsg(null)
    try { await p2pnasApi.rebalance(); setMsg('Rééquilibrage mis en file') } catch (e) { setErr(errMsg(e, 'Échec')) }
  }

  async function doRepair() {
    setErr(null); setMsg(null); setRepairing(true)
    try {
      const r = await p2pnasApi.runRepair()
      setRepair(r)
      setMsg(r.shards_replaced > 0
        ? `Réparation : ${r.shards_replaced} fragment(s) re-répliqué(s)`
        : 'Réparation : tout est sain, rien à faire')
    } catch (e) {
      setErr(errMsg(e, 'Échec de la réparation'))
    } finally {
      setRepairing(false)
    }
  }

  return (
    <section data-module="p2pnas" className="bg-surface-0 rounded-lg border border-border p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-primary" />
          <h2 className="font-semibold text-text-primary">Résilience & réparation</h2>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={rebalance}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-border text-sm hover:bg-surface-2 text-text-secondary"
          >
            <RefreshCw className="w-4 h-4" /> Rééquilibrer (en file)
          </button>
          <button
            onClick={doRepair}
            disabled={repairing}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-white text-sm hover:bg-primary-hover disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${repairing ? 'animate-spin' : ''}`} />
            {repairing ? 'Réparation…' : 'Lancer une réparation'}
          </button>
        </div>
      </div>
      <Feedback msg={msg} err={err} />
      <p className="text-sm text-text-tertiary mb-3">
        Vérifie chaque fichier et re-réplique les fragments dont l’hôte est devenu injoignable,
        tant qu’il reste assez de fragments pour reconstruire (≥ {status?.erasure.data_shards ?? 10} sur {(status?.erasure.data_shards ?? 10) + (status?.erasure.parity_shards ?? 4)}).
      </p>
      {repair && (
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 text-sm">
          <Stat label="Fichiers" value={String(repair.files_scanned)} />
          <Stat label="Chunks sains" value={String(repair.chunks_healthy)} />
          <Stat label="Réparés" value={String(repair.chunks_repaired)} />
          <Stat label="Fragments re-répliqués" value={String(repair.shards_replaced)} />
          <Stat label="Pairs joignables" value={`${repair.peers_reachable}/${repair.peers_total}`} />
          <Stat
            label="Irrécupérables"
            value={String(repair.chunks_unrepairable)}
            danger={repair.chunks_unrepairable > 0}
          />
        </div>
      )}
    </section>
  )
}

// ── maintenance: per-file durability (block 4) ────────────────────────────────

function FileDurability() {
  const geoAvailable = !!ModuleServiceRegistry.get('maps', 'geoip')
  const [files, setFiles] = useState<FileRow[]>([])
  const [health, setHealth] = useState<Record<string, FileHealth>>({})
  const [placement, setPlacement] = useState<Record<string, FilePlacement>>({})
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => { void p2pnasApi.listFiles().then(setFiles).catch(() => {}) }, [])

  async function checkHealth(f: FileRow) {
    setErr(null)
    try {
      const h = await p2pnasApi.fileHealth(f.file_id)
      setHealth(prev => ({ ...prev, [f.file_id]: h }))
    } catch (e) {
      setErr(errMsg(e, 'Vérification impossible'))
    }
  }

  async function togglePlacement(f: FileRow) {
    if (placement[f.file_id]) {
      setPlacement(prev => { const n = { ...prev }; delete n[f.file_id]; return n })
      return
    }
    setErr(null)
    try {
      const p = await p2pnasApi.filePlacement(f.file_id)
      setPlacement(prev => ({ ...prev, [f.file_id]: p }))
    } catch (e) {
      setErr(errMsg(e, 'Carte de placement indisponible'))
    }
  }

  return (
    <section data-module="p2pnas" className="bg-surface-0 rounded-lg border border-border p-5">
      <div className="flex items-center gap-2 mb-3">
        <ShieldAlert className="w-5 h-5 text-primary" />
        <h2 className="font-semibold text-text-primary">Durabilité des fichiers</h2>
      </div>
      <Feedback err={err} />
      {!geoAvailable && (
        <div className="mb-3 flex items-start gap-2 rounded-md bg-amber-50 border border-amber-200 px-3 py-2 text-xs text-amber-700">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
          <span>
            La localisation géographique des pairs (pays, carte) nécessite le module <strong>maps</strong>,
            qui n’est pas activé. Les fonctions géo restent indisponibles tant que maps n’est pas installé.
          </span>
        </div>
      )}
      {files.length === 0 ? (
        <p className="text-sm text-text-tertiary">Aucun fichier stocké.</p>
      ) : (
        <table className="w-full text-sm">
          <tbody>
            {files.map(f => {
              const h = health[f.file_id]
              const pl = placement[f.file_id]
              return (
                <Fragment key={f.file_id}>
                  <tr className="border-b border-border/60">
                    <td className="py-1.5 truncate max-w-xs" title={f.path}>{f.path}</td>
                    <td className="py-1.5 text-text-tertiary text-xs w-24">{formatBytes(f.size)}</td>
                    <td className="py-1.5 w-56">{h ? <HealthBadge h={h} /> : <span className="text-text-tertiary text-xs">—</span>}</td>
                    <td className="py-1.5 text-right whitespace-nowrap">
                      <button onClick={() => checkHealth(f)}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs hover:bg-surface-2 text-text-secondary hover:text-primary">
                        <FileSearch className="w-3.5 h-3.5" /> Vérifier
                      </button>
                      <button onClick={() => togglePlacement(f)}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs hover:bg-surface-2 text-text-secondary hover:text-primary">
                        <MapPin className="w-3.5 h-3.5" /> Carte
                      </button>
                    </td>
                  </tr>
                  {pl && (
                    <tr className="border-b border-border/60">
                      <td colSpan={4} className="py-2 pl-2">
                        <PlacementMap pl={pl} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      )}
    </section>
  )
}

/** Registers the p2pnas admin sections into the core admin console. */
export function registerP2pnasAdmin() {
  // No `label` on any section → each section IS the whole page of its group.
  ModuleAdminRegistry.register({ moduleId: 'p2pnas', id: 'node-status', group: 'overview', position: 10, Component: NodeStatusStats })
  ModuleAdminRegistry.register({ moduleId: 'p2pnas', id: 'metrics', group: 'overview', position: 20, Component: NodeMetricsSection })
  ModuleAdminRegistry.register({ moduleId: 'p2pnas', id: 'events', group: 'overview', position: 30, Component: EventLog })

  ModuleAdminRegistry.register({ moduleId: 'p2pnas', id: 'contribution', group: 'quotas', position: 10, Component: ContributionForm })
  ModuleAdminRegistry.register({ moduleId: 'p2pnas', id: 'user-quotas', group: 'quotas', position: 20, Component: UserQuotas })

  ModuleAdminRegistry.register({ moduleId: 'p2pnas', id: 'peers', group: 'peers', position: 10, Component: TrustedPeers })
  ModuleAdminRegistry.register({ moduleId: 'p2pnas', id: 'peer-map', group: 'peers', position: 20, Component: PeerMap })

  ModuleAdminRegistry.register({ moduleId: 'p2pnas', id: 'repair', group: 'maintenance', position: 10, Component: RepairActions })
  ModuleAdminRegistry.register({ moduleId: 'p2pnas', id: 'durability', group: 'maintenance', position: 20, Component: FileDurability })
}
