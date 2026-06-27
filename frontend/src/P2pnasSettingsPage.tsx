import { useEffect, useState } from 'react'
import { HardDrive, Users, Save, Plus } from 'lucide-react'
import { p2pnasApi, formatBytes, type NodeStatus, type QuotaRow, type PeerRow } from './api'

const GIB = 1024 * 1024 * 1024
const toBytes = (gib: string) => Math.round((parseFloat(gib) || 0) * GIB)
const toGib = (bytes: number) => (bytes / GIB).toFixed(2)

function errMsg(e: unknown, fallback: string): string {
  return (e as { response?: { data?: { error?: string } } })?.response?.data?.error || fallback
}

export default function P2pnasSettingsPage() {
  const [status, setStatus] = useState<NodeStatus | null>(null)
  const [isAdmin, setIsAdmin] = useState(false)
  const [quotas, setQuotas] = useState<QuotaRow[]>([])
  const [peers, setPeers] = useState<PeerRow[]>([])
  const [contrib, setContrib] = useState('')
  const [newUser, setNewUser] = useState('')
  const [newQuota, setNewQuota] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  async function load() {
    const s = await p2pnasApi.status()
    setStatus(s)
    setContrib(toGib(s.node.contributed_bytes))
    try {
      const [q, p] = await Promise.all([p2pnasApi.listQuotas(), p2pnasApi.listPeers()])
      setQuotas(q)
      setPeers(p)
      setIsAdmin(true)
    } catch {
      setIsAdmin(false)
    }
  }
  useEffect(() => { void load() }, [])

  async function run(fn: () => Promise<unknown>, ok: string) {
    setErr(null); setMsg(null)
    try { await fn(); setMsg(ok); await load() } catch (e) { setErr(errMsg(e, 'Échec')) }
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

        {/* ── Admin: peers ────────────────────────────────────────────── */}
        {isAdmin && (
          <section className="bg-surface-0 rounded-lg border border-border p-5">
            <div className="flex items-center gap-2 mb-3">
              <Users className="w-5 h-5 text-primary" />
              <h2 className="font-semibold text-text-primary">Pairs de confiance</h2>
            </div>
            {peers.length === 0 ? (
              <p className="text-sm text-text-tertiary">Aucun pair encore. Le réseau de résilience s’ajoutera en phase 3.</p>
            ) : (
              <table className="w-full text-sm">
                <thead><tr className="text-left text-xs text-text-tertiary border-b border-border">
                  <th className="py-1.5 font-medium">Pair</th><th className="py-1.5 font-medium">Adresse</th>
                  <th className="py-1.5 font-medium">Fiabilité</th><th className="py-1.5 font-medium">Contribué</th>
                </tr></thead>
                <tbody>
                  {peers.map(p => (
                    <tr key={p.peer_id} className="border-b border-border/60">
                      <td className="py-1.5 font-mono text-xs">{p.peer_id.slice(0, 12)}…</td>
                      <td className="py-1.5">{p.addr}</td>
                      <td className="py-1.5">{p.reliability_score.toFixed(0)}%</td>
                      <td className="py-1.5">{formatBytes(p.contributed_bytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        )}
      </div>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md bg-surface-1 px-3 py-2">
      <div className="text-xs text-text-tertiary">{label}</div>
      <div className="text-text-primary font-medium">{value}</div>
    </div>
  )
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
