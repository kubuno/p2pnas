# p2pnas — frontend

L'interface « My Cloud » (React, `@kubuno/sdk` / `@kubuno/ui`, réutilisant les
composants `@kubuno/drive`) est implémentée en **phase 2**.

Pour l'instant le module expose uniquement son API :
- `GET /api/v1/p2pnas/status` — état du nœud (capacité, pairs)
- `GET /api/v1/p2pnas/quota/me` — quota « My Cloud » de l'utilisateur
- `GET|POST /api/v1/p2pnas/admin/quotas` — allocation des quotas (admin)
- `GET /api/v1/p2pnas/admin/peers` — pairs de confiance (admin)
