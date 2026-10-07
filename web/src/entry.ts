/**
 * p2pnas module entry — loaded at runtime by the host, which calls `register()`.
 *
 * p2pnas declares NO launcher app / sidebar entry: it is a storage backend. It
 * publishes a "My Cloud" mount through ModuleServiceRegistry, which Drive picks
 * up and shows right after "Mon Drive". The mount is only offered to a user the
 * admin has actually granted a quota — otherwise My Cloud stays hidden. All
 * node administration lives in the core admin console (Modules ▸ p2pnas).
 */
import { ModuleServiceRegistry, SDK_VERSION, api, useAuthStore } from '@kubuno/sdk'
import './index.css'
import { myCloudSource } from './myCloudSource'
import { registerP2pnasAdmin } from './admin/P2pnasAdminPanel'

export const sdkVersion = SDK_VERSION

// The mount is shown only once we've confirmed the connected user has a quota.
let mountAvailable = false

/**
 * Runs `task` once a user is signed in — immediately if a session is already
 * restored, otherwise on the first one to appear. The host imports module
 * bundles before authentication so that public routes exist, so asking for the
 * connected user's quota from `register()` would only earn a 401.
 */
function whenSignedIn(task: () => void): void {
  if (useAuthStore.getState().user) { task(); return }
  const stop = useAuthStore.subscribe((state) => {
    if (state.user) { stop(); task() }
  })
}

async function refreshAvailability() {
  try {
    const { data } = await api.get<{ quota_bytes: number }>('/p2pnas/quota/me')
    mountAvailable = (data?.quota_bytes ?? 0) > 0
  } catch {
    mountAvailable = false // module reachable but no quota / not entitled
  }
  // Let the Drive sidebar recompute its module mounts now the answer is known.
  window.dispatchEvent(new CustomEvent('kubuno:module-mounts-changed'))
}

export function register() {
  // Storage mount(s) this module provides to Drive. Drive enumerates active
  // modules and calls this; an empty array means "no mount for this user".
  ModuleServiceRegistry.publish('p2pnas', {
    getStorageMounts: () => (mountAvailable ? [{ key: 'my-cloud', name: 'My Cloud' }] : []),
    getStorageSource: (_key: string) => myCloudSource(),
  })
  whenSignedIn(() => { void refreshAvailability() })

  // Node administration, rendered inside the core admin console.
  registerP2pnasAdmin()
}
