/**
 * p2pnas module entry — loaded at runtime by the host, which calls `register()`.
 * Shared specifiers (react, @kubuno/sdk, @ui…) are `external` and resolved by the
 * host import map. `sdkVersion` lets the host reject a contract mismatch.
 */
import { lazy } from 'react'
import { RouteRegistry, ModuleSettingsRegistry, WaffleAppRegistry, SDK_VERSION } from '@kubuno/sdk'
import './index.css'
import P2pnasLogo from './P2pnasLogo'

export const sdkVersion = SDK_VERSION

export function register() {
  // App-launcher (waffle) entry → "My Cloud".
  WaffleAppRegistry.register('p2pnas', 'My Cloud', [
    { id: 'p2pnas', label: 'My Cloud', Icon: P2pnasLogo, path: '/p2pnas' },
  ])

  // Header gear opens the per-user settings while in /p2pnas.
  ModuleSettingsRegistry.register('p2pnas')

  const MyCloudApp = lazy(() => import('./MyCloudApp'))
  const SettingsPage = lazy(() => import('./P2pnasSettingsPage'))
  RouteRegistry.register('p2pnas', MyCloudApp)
  RouteRegistry.register('p2pnas/settings', SettingsPage)
}
