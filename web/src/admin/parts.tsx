// Shared presentational pieces and helpers for the p2pnas admin panel. These
// were extracted from the former per-user settings page so each admin section
// can reuse them without duplicating markup.
import { useState } from 'react'
import { AlertTriangle, ShieldAlert, CheckCircle2, HardDriveDownload, Save } from 'lucide-react'
import { formatBytes, type FileHealth, type FilePlacement, type QuotaRow, type EventRow, type PeerRow } from '../api'

/** A single marker on the peers map, rendered by the maps module's MiniMap. */
export type PeerMarker = { lat: number; lng: number; label?: string; color?: string }

const GIB = 1024 * 1024 * 1024
export const toBytes = (gib: string) => Math.round((parseFloat(gib) || 0) * GIB)
export const toGib = (bytes: number) => (bytes / GIB).toFixed(2)

export function errMsg(e: unknown, fallback: string): string {
  return (e as { response?: { data?: { error?: string } } })?.response?.data?.error || fallback
}

/** A peer is considered live if it answered a probe within the last ~3 min. */
export function isLive(p: PeerRow): boolean {
  if (!p.last_seen) return false
  return Date.now() - new Date(p.last_seen).getTime() < 3 * 60 * 1000
}

/**
 * A control-plane event, in a sentence. The raw `kind` is the last resort: the
 * log is read to find out what the node did, and a bare slug says nothing about
 * a quota granted without anyone asking, or a peer that left the network.
 */
export function eventLabel(ev: EventRow): string {
  const p = ev.payload as {
    reachable_shards?: number; needed?: number; file_id?: string
    peer_id?: string; addr?: string; ip?: string; reason?: string
    user_id?: string; quota_bytes?: number
    files_deleted?: number; stored_bytes_freed?: number
  }
  switch (ev.kind) {
    case 'chunk_unrepairable':
      return `Chunk irrécupérable (${p.reachable_shards ?? '?'}/${p.needed ?? '?'} fragments joignables) — risque de perte de données`
    case 'peer_down':
      return `Pair déclaré hors-ligne : ${p.peer_id ?? '?'}${p.addr ? ` (${p.addr})` : ''}`
    case 'ip_changed':
      return `Adresse IP publique du nœud modifiée${p.ip ? ` → ${p.ip}` : ''} — rééquilibrage de proximité déclenché`
    case 'geo_unavailable':
      return 'Juridiction exigée mais service de géolocalisation indisponible — fragments conservés en local'
    case 'quota_defaulted':
      return `Quota par défaut attribué au premier envoi : ${formatBytes(p.quota_bytes ?? 0)}`
    case 'user_purged':
      return `Compte supprimé : ${p.files_deleted ?? 0} fichier(s) purgé(s), ${formatBytes(p.stored_bytes_freed ?? 0)} libéré(s)`
    default:
      return ev.kind
  }
}

export function Stat({ label, value, danger }: { label: string; value: string; danger?: boolean }) {
  return (
    <div className={`rounded-md px-3 py-2 ${danger ? 'bg-red-50' : 'bg-surface-1'}`}>
      <div className="text-xs text-text-tertiary">{label}</div>
      <div className={`font-medium ${danger ? 'text-red-600' : 'text-text-primary'}`}>{value}</div>
    </div>
  )
}

export function DiscoveryBadge({ label, on }: { label: string; on: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs ${on ? 'bg-green-50 text-green-700' : 'bg-surface-2 text-text-tertiary'}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${on ? 'bg-green-500' : 'bg-text-tertiary'}`} />
      {label}
    </span>
  )
}

export function HealthBadge({ h }: { h: FileHealth }) {
  if (!h.recoverable) {
    return <span className="inline-flex items-center gap-1 text-red-600 text-xs font-medium"><AlertTriangle className="w-3.5 h-3.5" /> À risque ({h.min_reachable}/{h.data_shards} requis)</span>
  }
  if (!h.single_failure_safe) {
    return <span className="inline-flex items-center gap-1 text-amber-600 text-xs font-medium"><ShieldAlert className="w-3.5 h-3.5" /> Récupérable ({h.min_reachable}/{h.total_shards})</span>
  }
  return <span className="inline-flex items-center gap-1 text-green-600 text-xs font-medium"><CheckCircle2 className="w-3.5 h-3.5" /> Sûr ({h.min_reachable}/{h.total_shards})</span>
}

function flagOf(country: string | null | undefined): string {
  if (!country || country.length !== 2) return '🌐'
  // ISO country code → regional-indicator emoji flag.
  return String.fromCodePoint(...[...country.toUpperCase()].map(c => 0x1f1e6 + c.charCodeAt(0) - 65))
}

export function PlacementMap({ pl }: { pl: FilePlacement }) {
  const total = pl.locations.reduce((n, l) => n + l.count, 0)
  const sorted = [...pl.locations].sort((a, b) => (a.kind === 'local' ? -1 : b.kind === 'local' ? 1 : (a.rtt_ms ?? 1e9) - (b.rtt_ms ?? 1e9)))
  return (
    <div className="space-y-1.5">
      {/* proportional bar */}
      <div className="flex h-2.5 rounded-full overflow-hidden bg-surface-2">
        {sorted.map(l => (
          <div key={l.id} title={`${l.id} — ${l.count} fragment(s)`}
            className={l.kind === 'local' ? 'bg-primary' : l.status === 'down' ? 'bg-red-400' : 'bg-green-400'}
            style={{ width: `${(l.count / total) * 100}%` }} />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {sorted.map(l => (
          <span key={l.id} className="inline-flex items-center gap-1.5">
            {l.kind === 'local'
              ? <HardDriveDownload className="w-3.5 h-3.5 text-primary" />
              : <span>{flagOf(l.country)}</span>}
            <span className="text-text-secondary">
              {l.kind === 'local' ? 'Ce nœud' : `${l.id.slice(0, 8)}…`}
            </span>
            <span className="font-medium text-text-primary">{l.count}</span>
            {l.kind === 'peer' && l.rtt_ms != null && <span className="text-text-tertiary">· {Math.round(l.rtt_ms)} ms</span>}
            {l.kind === 'peer' && l.status === 'down' && <span className="text-red-500">· hors-ligne</span>}
          </span>
        ))}
      </div>
    </div>
  )
}

export function LatencyBadge({ ms }: { ms: number }) {
  const color = ms < 50 ? 'text-green-600' : ms < 150 ? 'text-amber-600' : 'text-red-600'
  return <span className={`font-medium ${color}`}>{Math.round(ms)} ms</span>
}

export function ReliabilityBadge({ score }: { score: number }) {
  const color = score >= 80 ? 'text-green-600' : score >= 40 ? 'text-amber-600' : 'text-red-600'
  return <span className={`font-medium ${color}`}>{score.toFixed(0)}%</span>
}

export function QuotaEditor({ row, onSave }: { row: QuotaRow; onSave: (gib: string) => void }) {
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

/** Small inline feedback banner used by sections that mutate state. */
export function Feedback({ msg, err }: { msg?: string | null; err?: string | null }) {
  return (
    <>
      {msg && <div className="mb-3 rounded-md bg-green-50 border border-green-200 px-3 py-2 text-sm text-green-700">{msg}</div>}
      {err && <div className="mb-3 rounded-md bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">{err}</div>}
    </>
  )
}
