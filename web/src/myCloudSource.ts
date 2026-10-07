// A Drive StorageSource backed by the p2pnas HTTP API, exposed to Drive as a
// "My Cloud" mount (via ModuleServiceRegistry). It is **path-based** and mirrors
// the built-in remote/local sources so that the generic StorageExplorer renders
// it EXACTLY like "Mon Drive": folder tree, directory browsing, and the full
// context menu (new folder, rename, move, copy, delete, download, info).
import { localSource, type FileItem, type Folder } from '@kubuno/drive'
import { api } from '@kubuno/sdk'

type Source = ReturnType<typeof localSource>

interface P2pFolder { name: string; path: string }
interface P2pFile { name: string; path: string; file_id: string; size: number; created_at: string }

const IMG = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp', 'avif', 'ico']
const extOf = (n: string) => n.split('.').pop()?.toLowerCase() ?? ''

const MIME: Record<string, string> = {
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp',
  svg: 'image/svg+xml', pdf: 'application/pdf', txt: 'text/plain', md: 'text/markdown',
  json: 'application/json', csv: 'text/csv', mp3: 'audio/mpeg', wav: 'audio/wav',
  mp4: 'video/mp4', webm: 'video/webm', zip: 'application/zip',
}
const mimeOf = (name: string) => MIME[extOf(name)] ?? 'application/octet-stream'

const NOW = '1970-01-01T00:00:00Z'
const parentOf = (p: string) => p.split('/').slice(0, -1).join('/')
const baseOf = (p: string) => p.split('/').slice(-1)[0]
const joinPath = (dir: string | null, name: string) => (dir ? `${dir.replace(/\/+$/, '')}/${name}` : name)

// Path-keyed Folder/FileItem, matching how the remote source adapts path entries.
function toFolder(e: P2pFolder): Folder {
  return {
    id: e.path, name: e.name, parent_id: parentOf(e.path) || null, path: e.path,
    is_starred: false, is_protected: false, is_trashed: false, trashed_at: null,
    versioning_enabled: false, color: null, icon: null, owner_id: '',
    created_at: NOW, updated_at: NOW,
  }
}
function toFileItem(f: P2pFile): FileItem {
  return {
    id: f.path, name: f.name, folder_id: null, size_bytes: f.size,
    mime_type: mimeOf(f.name), is_starred: false, is_trashed: false,
    has_thumbnail: IMG.includes(extOf(f.name)), versioning_enabled: false,
    metadata: {}, owner_id: '', created_at: f.created_at, updated_at: f.created_at,
  }
}

async function blobOfPath(path: string): Promise<Blob> {
  const { data } = await api.get<Blob>('/p2pnas/download', { params: { path }, responseType: 'blob' })
  return data
}

export function myCloudSource(): Source {
  const base = localSource()
  return {
    ...base,
    key: 'p2pnas:my-cloud',
    capabilities: {
      ...base.capabilities,
      upload: true, mkdir: true, rename: true, move: true, copy: true,
      delete: true, info: true,
      trash: false, star: false, share: false, getLink: false, versions: false,
      color: false, compress: false, decompress: false, search: false,
      openWith: false, richModals: true, thumbnails: 'blob',
    },

    resolveRoot: async () => ({ id: '', name: 'My Cloud' }),

    resolveAncestors: async (id: string | null) => {
      if (!id) return []
      return id.split('/').filter(Boolean).map((seg, i, arr) => ({ id: arr.slice(0, i + 1).join('/'), name: seg }))
    },

    list: async (parentId: string | null) => {
      const { data } = await api.get<{ folders: P2pFolder[]; files: P2pFile[] }>('/p2pnas/browse', {
        params: { path: parentId ?? '' },
      })
      return { folders: data.folders.map(toFolder), files: data.files.map(toFileItem) }
    },

    createFolder: async (name: string, parentId: string | null) => {
      await api.post('/p2pnas/folders', { path: joinPath(parentId, name) })
    },

    rename: async (item: { id: string }, newName: string) => {
      await api.post('/p2pnas/rename', { from: item.id, to: joinPath(parentOf(item.id), newName) })
    },

    move: async (item: { id: string }, target: string | null) => {
      await api.post('/p2pnas/rename', { from: item.id, to: joinPath(target ?? '', baseOf(item.id)) })
    },

    copy: async (item: { id: string; type: string; name: string }, target: string | null) => {
      if (item.type !== 'file') return // folder copy handled by generic recursive transfer
      const blob = await blobOfPath(item.id)
      const f = new File([blob], item.name, { type: blob.type || 'application/octet-stream' })
      await api.post('/p2pnas/files', f, {
        params: { path: joinPath(target ?? '', item.name) },
        headers: { 'Content-Type': 'application/octet-stream' },
      })
    },

    trash: async (items: Array<{ id: string }>) => {
      for (const it of items) await api.post('/p2pnas/delete', { path: it.id })
    },
    remove: async (items: Array<{ id: string }>) => {
      for (const it of items) await api.post('/p2pnas/delete', { path: it.id })
    },

    uploadFile: async (file: File, parentId: string | null, onProgress?: (p: number) => void) => {
      const path = joinPath(parentId, file.name)
      await api.post('/p2pnas/files', file, {
        params: { path },
        headers: { 'Content-Type': 'application/octet-stream' },
        onUploadProgress: (e: { loaded: number; total?: number }) => {
          if (onProgress && e.total) onProgress(Math.round((e.loaded / e.total) * 100))
        },
      })
      return { id: path }
    },

    download: async (item: { id: string; name: string; type?: string }) => {
      if (item.type === 'folder') return
      const url = URL.createObjectURL(await blobOfPath(item.id))
      const a = document.createElement('a')
      a.href = url
      a.download = item.name
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    },

    readBlob: async (ref: { id: string }) => blobOfPath(ref.id),
    thumbnail: (file: FileItem) =>
      IMG.includes(extOf(file.name)) ? { kind: 'blob' as const, load: () => blobOfPath(file.id) } : { kind: 'none' as const },
    content: (file: FileItem) => ({ kind: 'blob' as const, load: () => blobOfPath(file.id) }),
  }
}
