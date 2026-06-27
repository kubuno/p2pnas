import { useCallback, useEffect, useRef, useState } from 'react'
import { useConfirm } from '@kubuno/sdk'
import { ConfirmDialog } from '@ui'
import { UploadCloud, Download, Trash2, File as FileIcon, Loader2, HardDrive, ShieldCheck } from 'lucide-react'
import { p2pnasApi, formatBytes, type FileRow, type MyQuota } from './api'

function errMsg(e: unknown, fallback: string): string {
  const r = (e as { response?: { data?: { error?: string } } })?.response
  return r?.data?.error || fallback
}

export default function MyCloudApp() {
  const [files, setFiles] = useState<FileRow[]>([])
  const [quota, setQuota] = useState<MyQuota | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const { confirm, confirmState, handleConfirm, handleCancel } = useConfirm()

  const reload = useCallback(async () => {
    try {
      const [f, q] = await Promise.all([p2pnasApi.listFiles(), p2pnasApi.quotaMe()])
      setFiles(f.sort((a, b) => a.path.localeCompare(b.path)))
      setQuota(q)
      setError(null)
    } catch (e) {
      setError(errMsg(e, 'Impossible de charger My Cloud'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void reload() }, [reload])

  const uploadFiles = useCallback(async (list: FileList | File[]) => {
    setBusy(true); setError(null)
    try {
      for (const file of Array.from(list)) {
        await p2pnasApi.upload(file.name, file)
      }
      await reload()
    } catch (e) {
      setError(errMsg(e, 'Échec de l’envoi'))
    } finally {
      setBusy(false)
    }
  }, [reload])

  async function download(f: FileRow) {
    try {
      const blob = await p2pnasApi.download(f.file_id)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = f.path.split('/').pop() || f.path
      document.body.appendChild(a); a.click(); a.remove()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(errMsg(e, 'Échec du téléchargement'))
    }
  }

  async function remove(f: FileRow) {
    const ok = await confirm({
      title: 'Supprimer',
      message: `Supprimer « ${f.path} » de My Cloud ? Cette action est définitive.`,
      variant: 'danger',
      confirmLabel: 'Supprimer',
    })
    if (!ok) return
    try {
      await p2pnasApi.remove(f.file_id)
      await reload()
    } catch (e) {
      setError(errMsg(e, 'Échec de la suppression'))
    }
  }

  const pct = quota && quota.quota_bytes > 0 ? Math.min(100, (quota.used_bytes / quota.quota_bytes) * 100) : 0
  const nearFull = pct >= 90

  return (
    <div className="h-full flex flex-col bg-surface-1" data-module="p2pnas">
      {/* ── Header: storage gauge ─────────────────────────────────────────── */}
      <div className="px-6 pt-5 pb-4 bg-surface-0 border-b border-border">
        <div className="flex items-center gap-2 mb-3">
          <HardDrive className="w-5 h-5 text-primary" />
          <h1 className="text-lg font-semibold text-text-primary">My Cloud</h1>
          <span className="ml-2 inline-flex items-center gap-1 text-xs text-text-tertiary">
            <ShieldCheck className="w-3.5 h-3.5" /> chiffré · résilient (RS&nbsp;10+4)
          </span>
        </div>
        {quota && (
          <div className="max-w-xl">
            <div className="h-2 rounded-full bg-surface-3 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${nearFull ? 'bg-red-500' : 'bg-primary'}`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <div className="mt-1.5 text-xs text-text-secondary">
              {formatBytes(quota.used_bytes)} utilisés sur {formatBytes(quota.quota_bytes)}
              {quota.quota_bytes > 0 ? ` · ${formatBytes(quota.available_bytes)} disponibles` : ' · aucun quota alloué (voir un administrateur)'}
            </div>
          </div>
        )}
      </div>

      {/* ── Upload zone ──────────────────────────────────────────────────── */}
      <div className="px-6 pt-4">
        <input
          ref={inputRef}
          type="file"
          multiple
          className="hidden"
          onChange={e => { if (e.target.files?.length) void uploadFiles(e.target.files); e.target.value = '' }}
        />
        <div
          onClick={() => inputRef.current?.click()}
          onDragOver={e => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={e => { e.preventDefault(); setDragOver(false); if (e.dataTransfer.files?.length) void uploadFiles(e.dataTransfer.files) }}
          className={`cursor-pointer rounded-lg border-2 border-dashed px-6 py-6 text-center transition-colors
            ${dragOver ? 'border-primary bg-primary-light/40' : 'border-border hover:border-primary/60 bg-surface-0'}`}
        >
          {busy ? (
            <div className="flex items-center justify-center gap-2 text-text-secondary">
              <Loader2 className="w-5 h-5 animate-spin" /> Chiffrement et envoi…
            </div>
          ) : (
            <div className="flex flex-col items-center gap-1 text-text-secondary">
              <UploadCloud className="w-7 h-7 text-primary" />
              <div className="text-sm"><span className="text-primary font-medium">Importer des fichiers</span> ou glissez-les ici</div>
              <div className="text-xs text-text-tertiary">chiffrés localement avant distribution</div>
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="mx-6 mt-3 rounded-md bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">{error}</div>
      )}

      {/* ── File list ────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-auto px-6 py-4">
        {loading ? (
          <div className="flex items-center justify-center h-40 text-text-tertiary">
            <Loader2 className="w-5 h-5 animate-spin" />
          </div>
        ) : files.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-text-tertiary">
            <FileIcon className="w-10 h-10 mb-2 opacity-40" />
            <div className="text-sm">Aucun fichier pour l’instant</div>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-text-tertiary border-b border-border">
                <th className="py-2 font-medium">Nom</th>
                <th className="py-2 font-medium w-28">Taille</th>
                <th className="py-2 font-medium w-44">Ajouté le</th>
                <th className="py-2 font-medium w-24 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {files.map(f => (
                <tr key={f.file_id} className="border-b border-border/60 hover:bg-surface-0 group">
                  <td className="py-2.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <FileIcon className="w-4 h-4 text-text-tertiary shrink-0" />
                      <span className="truncate text-text-primary">{f.path}</span>
                    </div>
                  </td>
                  <td className="py-2.5 text-text-secondary">{formatBytes(f.size)}</td>
                  <td className="py-2.5 text-text-secondary">{new Date(f.created_at).toLocaleString('fr-FR')}</td>
                  <td className="py-2.5">
                    <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button title="Télécharger" onClick={() => download(f)} className="p-1.5 rounded hover:bg-surface-2 text-text-secondary hover:text-primary">
                        <Download className="w-4 h-4" />
                      </button>
                      <button title="Supprimer" onClick={() => remove(f)} className="p-1.5 rounded hover:bg-surface-2 text-text-secondary hover:text-red-600">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {confirmState && <ConfirmDialog {...confirmState} onConfirm={handleConfirm} onCancel={handleCancel} />}
    </div>
  )
}
