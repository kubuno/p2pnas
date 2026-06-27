// A Drive StorageSource backed by the p2pnas HTTP API, exposed to Drive as a
// "My Cloud" mount (via ModuleServiceRegistry). p2pnas is a FLAT store (no
// folders/rename/star/share), so only list/upload/download/delete are enabled;
// the unsupported operations are turned off via `capabilities` and inherited
// (never called) from the local source.
import { localSource, type FileItem } from '@kubuno/drive'
import { api } from '@kubuno/sdk'

type Source = ReturnType<typeof localSource>

interface P2pFile {
  file_id: string
  path: string
  size: number
  created_at: string
  user_id: string
}

const MIME: Record<string, string> = {
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp',
  svg: 'image/svg+xml', pdf: 'application/pdf', txt: 'text/plain', md: 'text/markdown',
  json: 'application/json', csv: 'text/csv', mp3: 'audio/mpeg', wav: 'audio/wav',
  mp4: 'video/mp4', webm: 'video/webm', zip: 'application/zip',
}
function mimeOf(name: string): string {
  return MIME[name.split('.').pop()?.toLowerCase() ?? ''] ?? 'application/octet-stream'
}

function toFileItem(f: P2pFile): FileItem {
  const name = f.path.split('/').pop() || f.path
  return {
    id: f.file_id,
    name,
    folder_id: null,
    size_bytes: f.size,
    mime_type: mimeOf(name),
    is_starred: false,
    is_trashed: false,
    has_thumbnail: false,
    versioning_enabled: false,
    metadata: {},
    owner_id: f.user_id,
    created_at: f.created_at,
    updated_at: f.created_at,
  }
}

async function blobOf(id: string): Promise<Blob> {
  const { data } = await api.get<Blob>(`/p2pnas/files/${id}`, { responseType: 'blob' })
  return data
}

export function myCloudSource(): Source {
  const base = localSource()
  return {
    ...base,
    key: 'p2pnas:my-cloud',
    capabilities: {
      ...base.capabilities,
      upload: true, delete: true,
      mkdir: false, rename: false, move: false, copy: false, trash: false,
      star: false, share: false, getLink: false, versions: false, color: false,
      compress: false, decompress: false, info: false, search: false,
      openWith: false, richModals: false, thumbnails: 'none',
    },
    resolveRoot: async () => ({ id: null, name: 'My Cloud' }),
    resolveAncestors: async () => [],
    list: async (parentId: string | null) => {
      if (parentId !== null) return { folders: [], files: [] }
      const { data } = await api.get<{ files: P2pFile[] }>('/p2pnas/files')
      return { folders: [], files: data.files.map(toFileItem) }
    },
    uploadFile: async (file: File, _parent: string | null, onProgress?: (p: number) => void) => {
      const { data } = await api.post<{ file_id: string }>('/p2pnas/files', file, {
        params: { path: file.name },
        headers: { 'Content-Type': 'application/octet-stream' },
        onUploadProgress: (e: { loaded: number; total?: number }) => {
          if (onProgress && e.total) onProgress(Math.round((e.loaded / e.total) * 100))
        },
      })
      return { id: data.file_id }
    },
    remove: async (items: Array<{ id: string }>) => {
      for (const it of items) await api.delete(`/p2pnas/files/${it.id}`)
    },
    download: async (item: { id: string; name: string }) => {
      const url = URL.createObjectURL(await blobOf(item.id))
      const a = document.createElement('a')
      a.href = url
      a.download = item.name
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    },
    readBlob: async (ref: { id: string }) => blobOf(ref.id),
    thumbnail: () => ({ kind: 'none' as const }),
    content: (file: FileItem) => ({ kind: 'blob' as const, load: () => blobOf(file.id) }),
  }
}
