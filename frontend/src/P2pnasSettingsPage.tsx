import { useEffect, useState } from 'react'
import { HardDrive, Users, Save, Plus, ShieldCheck, RefreshCw, Trash2, Activity, AlertTriangle, Wifi, WifiOff, Gauge, Radar, ShieldAlert, CheckCircle2, FileSearch } from 'lucide-react'
import { useConfirm } from '@kubuno/sdk'
import { ConfirmDialog } from '@ui'
import {
  p2pnasApi, formatBytes, timeAgo,
  type NodeStatus, type QuotaRow, type PeerRow, type RepairReport, type EventRow,
  type NodeMetrics, type FileHealth, type FileRow,
} from './api'

const GIB = 1024 * 1024 * 1024
const toBytes = (gib: string) => Math.round((parseFloat(gib) || 0) * GIB)
const toGib = (bytes: number) => (bytes / GIB).toFixed(2)

function errMsg(e: unknown, fallback: string): string {
  return (e as { response?: { data?: { error?: string } } })?.response?.data?.error || fallback
}

/** A peer is considered live if it answered a probe within the last ~3 min. */
function isLive(p: PeerRow): boolean {
  if (!p.last_seen) return false
  return Date.now() - new Date(p.last_seen).getTime() < 3 * 60 * 1000
}

export default function P2pnasSettingsPage() {
  const [status, setStatus] = useState<NodeStatus | null>(null)
  const [isAdmin, setIsAdmin] = useState(false)
  const [quotas, setQuotas] = useState<QuotaRow[]>([])
  const [peers, setPeers] = useState<PeerRow[]>([])
  const [events, setEvents] = useState<EventRow[]>([])
  const [contrib, setContrib] = useState('')
  const [newUser, setNewUser] = useState('')
  const [newQuota, setNewQuota] = useState('')
  const [newPeer, setNewPeer] = useState('')
  const [repair, setRepair] = useState<RepairReport | null>(null)
  const [repairing, setRepairing] = useState(false)
  const [metrics, setMetrics] = useState<NodeMetrics | null>(null)
  const [files, setFiles] = useState<FileRow[]>([])
  const [health, setHealth] = useState<Record<string, FileHealth>>({})
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const { confirm, confirmState, handleConfirm, handleCancel } = useConfirm()

  async function load() {
    const s = await p2pnasApi.status()
    setStatus(s)
    setContrib(toGib(s.node.contributed_bytes))
    try {
      const [q, p, ev, m, f] = await Promise.all([
        p2pnasApi.listQuotas(), p2pnasApi.listPeers(), p2pnasApi.listEvents(),
        p2pnasApi.metrics(), p2pnasApi.listFiles(),
      ])
      setQuotas(q); setPeers(p); setEvents(ev); setMetrics(m); setFiles(f); setIsAdmin(true)
    } catch {
      setIsAdmin(false)
    }
  }

  async function checkHealth(f: FileRow) {
    setErr(null)
    try {
      const h = await p2pnasApi.fileHealth(f.file_id)
      setHealth(prev => ({ ...prev, [f.file_id]: h }))
    } catch (e) {
      setErr(errMsg(e, 'Vérification impossible'))
    }
  }
  useEffect(() => { void load() }, [])

  async function run(fn: () => Promise<unknown>, ok: string) {
    setErr(null); setMsg(null)
    try { await fn(); setMsg(ok); await load() } catch (e) { setErr(errMsg(e, 'Échec')) }
  }

  async function doRepair() {
    setErr(null); setMsg(null); setRepairing(true)
    try {
      const r = await p2pnasApi.runRepair()
      setRepair(r)
      setMsg(r.shards_replaced > 0
        ? `Réparation : ${r.shards_replaced} fragment(s) re-répliqué(s)`
        : 'Réparation : tout est sain, rien à faire')
      await load()
    } catch (e) {
      setErr(errMsg(e, 'Échec de la réparation'))
    } finally {
      setRepairing(false)
    }
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
    <div className="h-full overflow-auto bg-surface-1" data-module="p2pnas">
      <div className="max-w-3xl mx-auto px-6 py-6 space-y-6">
        <h1 className="text-xl font-semibold text-text-primary">Paramètres — My Cloud</h1>

        {msg && <div className="rounded-md bg-green-50 border border-green-200 px-3 py-2 text-sm text-green-700">{msg}</div>}
        {err && <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">{err}</div>}

        {/* ── Node ─────────────────────────────────────────────────────── */}
        <section className="bg-surface-0 rounded-lg border border-border p-5">
          <div className="flex items-center gap-2 mb-3">
            <HardDrive className="w-5 h-5 text-primary" />
            <h2 className="font-semibold text-text-primary">Nœud de stockage</h2>
          </div>
          {status && (
            <div className="grid grid-cols-3 gap-4 text-sm mb-4">
              <Stat label="Contribué" value={formatBytes(status.node.contributed_bytes)} />
              <Stat label="Utilisé" value={formatBytes(status.node.used_bytes)} />
              <Stat label="Disponible" value={formatBytes(status.node.available_bytes)} />
            </div>
          )}
          {isAdmin ? (
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
                onClick={() => run(() => p2pnasApi.setContribution(toBytes(contrib)), 'Contribution mise à jour')}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-white text-sm hover:bg-primary-hover"
              >
                <Save className="w-4 h-4" /> Enregistrer
              </button>
            </div>
          ) : (
            <p className="text-sm text-text-tertiary">La contribution et les quotas sont gérés par un administrateur.</p>
          )}
        </section>

        {/* ── Admin: résilience & réparation ──────────────────────────── */}
        {isAdmin && (
          <section className="bg-surface-0 rounded-lg border border-border p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-primary" />
                <h2 className="font-semibold text-text-primary">Résilience & réparation</h2>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => run(() => p2pnasApi.rebalance(), 'Rééquilibrage mis en file')}
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
        )}

        {/* ── Admin: métriques du nœud + état de la découverte ────────── */}
        {isAdmin && metrics && (
          <section className="bg-surface-0 rounded-lg border border-border p-5">
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
        )}

        {/* ── Durabilité par fichier ──────────────────────────────────── */}
        {isAdmin && files.length > 0 && (
          <section className="bg-surface-0 rounded-lg border border-border p-5">
            <div className="flex items-center gap-2 mb-3">
              <ShieldAlert className="w-5 h-5 text-primary" />
              <h2 className="font-semibold text-text-primary">Durabilité des fichiers</h2>
            </div>
            <table className="w-full text-sm">
              <tbody>
                {files.map(f => {
                  const h = health[f.file_id]
                  return (
                    <tr key={f.file_id} className="border-b border-border/60">
                      <td className="py-1.5 truncate max-w-xs" title={f.path}>{f.path}</td>
                      <td className="py-1.5 text-text-tertiary text-xs w-24">{formatBytes(f.size)}</td>
                      <td className="py-1.5 w-56">{h ? <HealthBadge h={h} /> : <span className="text-text-tertiary text-xs">—</span>}</td>
                      <td className="py-1.5 text-right">
                        <button onClick={() => checkHealth(f)}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs hover:bg-surface-2 text-text-secondary hover:text-primary">
                          <FileSearch className="w-3.5 h-3.5" /> Vérifier
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </section>
        )}

        {/* ── Admin: peers ────────────────────────────────────────────── */}
        {isAdmin && (
          <section className="bg-surface-0 rounded-lg border border-border p-5">
            <div className="flex items-center gap-2 mb-3">
              <Users className="w-5 h-5 text-primary" />
              <h2 className="font-semibold text-text-primary">Pairs de confiance</h2>
              <span className="text-xs text-text-tertiary ml-1">
                ({peers.filter(isLive).length} en ligne / {peers.length})
              </span>
            </div>
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
          </section>
        )}

        {/* ── Admin: quotas ───────────────────────────────────────────── */}
        {isAdmin && (
          <section className="bg-surface-0 rounded-lg border border-border p-5">
            <h2 className="font-semibold text-text-primary mb-3">Quotas par utilisateur</h2>
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
        )}

        {/* ── Admin: events ───────────────────────────────────────────── */}
        {isAdmin && events.length > 0 && (
          <section className="bg-surface-0 rounded-lg border border-border p-5">
            <div className="flex items-center gap-2 mb-3">
              <Activity className="w-5 h-5 text-primary" />
              <h2 className="font-semibold text-text-primary">Journal d’événements</h2>
            </div>
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
          </section>
        )}
      </div>

      {confirmState && <ConfirmDialog {...confirmState} onConfirm={handleConfirm} onCancel={handleCancel} />}
    </div>
  )
}

function eventLabel(ev: EventRow): string {
  if (ev.kind === 'chunk_unrepairable') {
    const p = ev.payload as { reachable_shards?: number; needed?: number; file_id?: string }
    return `Chunk irrécupérable (${p.reachable_shards ?? '?'}/${p.needed ?? '?'} fragments joignables) — risque de perte de données`
  }
  return ev.kind
}

function Stat({ label, value, danger }: { label: string; value: string; danger?: boolean }) {
  return (
    <div className={`rounded-md px-3 py-2 ${danger ? 'bg-red-50' : 'bg-surface-1'}`}>
      <div className="text-xs text-text-tertiary">{label}</div>
      <div className={`font-medium ${danger ? 'text-red-600' : 'text-text-primary'}`}>{value}</div>
    </div>
  )
}

function DiscoveryBadge({ label, on }: { label: string; on: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs ${on ? 'bg-green-50 text-green-700' : 'bg-surface-2 text-text-tertiary'}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${on ? 'bg-green-500' : 'bg-text-tertiary'}`} />
      {label}
    </span>
  )
}

function HealthBadge({ h }: { h: FileHealth }) {
  if (!h.recoverable) {
    return <span className="inline-flex items-center gap-1 text-red-600 text-xs font-medium"><AlertTriangle className="w-3.5 h-3.5" /> À risque ({h.min_reachable}/{h.data_shards} requis)</span>
  }
  if (!h.single_failure_safe) {
    return <span className="inline-flex items-center gap-1 text-amber-600 text-xs font-medium"><ShieldAlert className="w-3.5 h-3.5" /> Récupérable ({h.min_reachable}/{h.total_shards})</span>
  }
  return <span className="inline-flex items-center gap-1 text-green-600 text-xs font-medium"><CheckCircle2 className="w-3.5 h-3.5" /> Sûr ({h.min_reachable}/{h.total_shards})</span>
}

function LatencyBadge({ ms }: { ms: number }) {
  const color = ms < 50 ? 'text-green-600' : ms < 150 ? 'text-amber-600' : 'text-red-600'
  return <span className={`font-medium ${color}`}>{Math.round(ms)} ms</span>
}

function ReliabilityBadge({ score }: { score: number }) {
  const color = score >= 80 ? 'text-green-600' : score >= 40 ? 'text-amber-600' : 'text-red-600'
  return <span className={`font-medium ${color}`}>{score.toFixed(0)}%</span>
}

function QuotaEditor({ row, onSave }: { row: QuotaRow; onSave: (gib: string) => void }) {
  const [gib, setGib] = useState(toGib(row.quota_bytes))
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="font-mono text-xs text-text-secondary flex-1 truncate">{row.user_id}</span>
      <span className="text-text-tertiary text-xs w-28">{formatBytes(row.used_bytes)} util.</span>
      <input value={gib} onChange={e => setGib(e.target.value)} type="number" min="0" step="0.1"
        className="w-24 px-2 py-1 rounded border border-border bg-surface-0 text-text-primary" />
      <span className="text-text-tertiary text-xs">Go</span>
      <button onClick={() => onSave(gib)} className="p-1.5 rounded hover:bg-surface-2 text-text-secondary hover:text-primary" title="Enregistrer">
        <Save className="w-4 h-4" />
      </button>
    </div>
  )
}
