import { api as apiClient } from '@kubuno/sdk'

export interface FileRow {
  file_id: string
  user_id: string
  path: string
  size: number
  stored_bytes: number
  chunk_count: number
  created_at: string
}

export interface NodeStatus {
  node: { contributed_bytes: number; used_bytes: number; available_bytes: number }
  peers: number
  erasure: { data_shards: number; parity_shards: number }
  version: string
}

export interface MyQuota {
  quota_bytes: number
  used_bytes: number
  available_bytes: number
}

export interface QuotaRow {
  user_id: string
  quota_bytes: number
  used_bytes: number
  available_bytes: number
}

export interface PeerRow {
  peer_id: string
  addr: string
  reliability_score: number
  contributed_bytes: number
  last_seen: string | null
}

export interface RepairReport {
  files_scanned: number
  chunks_scanned: number
  chunks_healthy: number
  chunks_repaired: number
  shards_replaced: number
  chunks_unrepairable: number
  peers_total: number
  peers_reachable: number
}

export interface EventRow {
  id: number
  kind: string
  payload: Record<string, unknown>
  created_at: string
}

export interface NodeMetrics {
  node: { contributed_bytes: number; used_bytes: number; hosted_bytes: number; available_bytes: number }
  storage: { files: number; chunks: number; stored_bytes: number; hosted_shards: number }
  peers: { total: number; active: number; down: number }
  jobs: { pending: number; running: number }
  discovery: { mdns: boolean; dht: boolean }
  risk: { unrepairable_events: number }
}

export interface FileHealth {
  file_id: string
  path: string
  size: number
  chunks: number
  data_shards: number
  total_shards: number
  min_reachable: number
  fully_redundant: boolean
  recoverable: boolean
  single_failure_safe: boolean
  at_risk: boolean
}

export const p2pnasApi = {
  status:    () => apiClient.get<NodeStatus>('/p2pnas/status').then(r => r.data),
  quotaMe:   () => apiClient.get<MyQuota>('/p2pnas/quota/me').then(r => r.data),
  listFiles: () => apiClient.get<{ files: FileRow[] }>('/p2pnas/files').then(r => r.data.files),

  upload: (path: string, blob: Blob) =>
    apiClient
      .post<{ file_id: string; path: string; size: number }>('/p2pnas/files', blob, {
        params: { path },
        headers: { 'Content-Type': 'application/octet-stream' },
      })
      .then(r => r.data),

  download: (fileId: string) =>
    apiClient.get<Blob>(`/p2pnas/files/${fileId}`, { responseType: 'blob' }).then(r => r.data),

  remove: (fileId: string) => apiClient.delete(`/p2pnas/files/${fileId}`),

  // ── Admin ────────────────────────────────────────────────────────────────
  listQuotas: () =>
    apiClient.get<{ quotas: QuotaRow[] }>('/p2pnas/admin/quotas').then(r => r.data.quotas),
  setQuota: (userId: string, quotaBytes: number) =>
    apiClient.post('/p2pnas/admin/quotas', { user_id: userId, quota_bytes: quotaBytes }),
  setContribution: (bytes: number) =>
    apiClient.post('/p2pnas/admin/contribution', { bytes }),
  listPeers: () =>
    apiClient.get<{ peers: PeerRow[] }>('/p2pnas/admin/peers').then(r => r.data.peers),
  addPeer: (addr: string) =>
    apiClient.post('/p2pnas/admin/peers', { addr }),
  removePeer: (peerId: string) =>
    apiClient.delete(`/p2pnas/admin/peers/${encodeURIComponent(peerId)}`),
  runRepair: () =>
    apiClient.post<{ repair: RepairReport }>('/p2pnas/admin/repair').then(r => r.data.repair),
  listEvents: () =>
    apiClient.get<{ events: EventRow[] }>('/p2pnas/admin/events').then(r => r.data.events),
  metrics: () =>
    apiClient.get<NodeMetrics>('/p2pnas/admin/metrics').then(r => r.data),
  rebalance: () =>
    apiClient.post('/p2pnas/admin/rebalance'),
  fileHealth: (fileId: string) =>
    apiClient.get<FileHealth>(`/p2pnas/files/${fileId}/health`).then(r => r.data),
}

/** Relative "il y a …" formatting for last_seen / event timestamps. */
export function timeAgo(iso: string | null): string {
  if (!iso) return 'jamais'
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return "à l'instant"
  if (s < 3600) return `il y a ${Math.floor(s / 60)} min`
  if (s < 86400) return `il y a ${Math.floor(s / 3600)} h`
  return `il y a ${Math.floor(s / 86400)} j`
}

export function formatBytes(n: number): string {
  if (n <= 0) return '0 o'
  const u = ['o', 'Ko', 'Mo', 'Go', 'To']
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)))
  return `${(n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${u[i]}`
}
