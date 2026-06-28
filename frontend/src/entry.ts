/**
 * p2pnas module entry — loaded at runtime by the host, which calls `register()`.
 *
 * p2pnas declares NO launcher app / sidebar entry: it is a storage backend. It
 * publishes a "My Cloud" mount through ModuleServiceRegistry, which Drive picks
 * up and shows right after "Mon Drive". The mount is only offered to a user the
 * admin has actually granted a quota — otherwise My Cloud stays hidden. Only the
 * admin settings page has a route.
 */
import { lazy } from 'react'
import { RouteRegistry, ModuleSettingsRegistry, ModuleServiceRegistry, SDK_VERSION, api } from '@kubuno/sdk'
import './index.css'
import { myCloudSource } from './myCloudSource'

export const sdkVersion = SDK_VERSION

// The mount is shown only once we've confirmed the connected user has a quota.
let mountAvailable = false

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
  void refreshAvailability()

  // Admin/settings page (reachable via the admin module list `settings_path`).
  ModuleSettingsRegistry.register('p2pnas')
  const SettingsPage = lazy(() => import('./P2pnasSettingsPage'))
  RouteRegistry.register('p2pnas/settings', SettingsPage)
}
