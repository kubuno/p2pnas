/**
 * p2pnas module entry — loaded at runtime by the host, which calls `register()`.
 *
 * p2pnas declares NO launcher app / sidebar entry: it is a storage backend. It
 * publishes a "My Cloud" mount through ModuleServiceRegistry, which Drive picks
 * up and shows next to "Mon Drive". Only the admin settings page has a route.
 */
import { lazy } from 'react'
import { RouteRegistry, ModuleSettingsRegistry, ModuleServiceRegistry, SDK_VERSION } from '@kubuno/sdk'
import './index.css'
import { myCloudSource } from './myCloudSource'

export const sdkVersion = SDK_VERSION

export function register() {
  // Storage mount(s) this module provides to Drive. Drive enumerates active
  // modules and calls these; returning undefined means "no mounts".
  ModuleServiceRegistry.publish('p2pnas', {
    getStorageMounts: () => [{ key: 'my-cloud', name: 'My Cloud' }],
    getStorageSource: (_key: string) => myCloudSource(),
  })

  // Admin/settings page (reachable via the admin module list `settings_path`).
  ModuleSettingsRegistry.register('p2pnas')
  const SettingsPage = lazy(() => import('./P2pnasSettingsPage'))
  RouteRegistry.register('p2pnas/settings', SettingsPage)
}
