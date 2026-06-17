import type { IPlugin } from '@shell/core/types';
import {
  PRODUCT,
  BLANK_CLUSTER,
  PAGE_TYPES,
  PAGES,
  ROUTE_NAMES,
} from './config/product';
import store from './store/suse-ai-up';

interface RancherStore {
  registerModule?: (name: string, module: unknown) => void;
}

export function init($plugin: IPlugin, rancherStore: RancherStore) {
  const { product, virtualType, basicType, weightType, weightGroup } = $plugin.DSL(rancherStore as any, PRODUCT);

  rancherStore.registerModule?.(PRODUCT, store);

  product({
    name:     PRODUCT,
    category: 'global',
    icon:     'fork',
    inStore:  'management',
    weight:   80,
    to:       {
      name:   ROUTE_NAMES.HOME,
      params: { product: PRODUCT, cluster: BLANK_CLUSTER },
      meta:   { product: PRODUCT },
    },
  });

  // Virtual types make each page addressable via the product DSL.
  PAGES.forEach((p) => {
    virtualType({
      name:  p.name,
      label: p.label,
      route: {
        name:   p.route,
        params: { product: PRODUCT, cluster: BLANK_CLUSTER },
        meta:   { product: PRODUCT },
      },
    });
  });

  // Side-menu grouping: all pages live under a single "SUSE AI Up" group.
  basicType(
    [
      PAGE_TYPES.HOME,
      PAGE_TYPES.MCP_GATEWAY,
      PAGE_TYPES.MCP_REGISTRY,
      PAGE_TYPES.REGISTRY_SOURCES,
      PAGE_TYPES.VIRTUAL_MCP,
      PAGE_TYPES.SMART_AGENTS,
      PAGE_TYPES.DISCOVERY,
      PAGE_TYPES.PLUGINS,
      PAGE_TYPES.SETTINGS,
    ],
    PAGE_TYPES.GROUP,
  );

  PAGES.forEach((p) => weightType(p.name, p.weight, true));

  // Position the whole group above Rancher's root pseudo-group (weight 1000).
  // Per https://extensions.rancher.io/extensions/next/api/nav/side-menu —
  // weightType handles within-group ordering; weightGroup positions the group
  // itself. Without this the group floats at the default position regardless
  // of how clean the per-entry weights are.
  weightGroup(PAGE_TYPES.GROUP, 1001, true);
}
