// Central product constants used by index.ts, product.ts, routing.ts,
// and the page stubs. Keep slug/label changes here.

export const PRODUCT = 'suse-ai-up';
export const PRODUCT_LABEL = 'Universal Proxy';
export const BLANK_CLUSTER = '_';

// Page slugs double as `basicType` registration keys. `settings-up` is
// deliberately suffixed to avoid colliding with Rancher's built-in
// `settings` resource type (the old extension used the same trick).
export const PAGE_TYPES = {
  HOME:         'home',
  MCP_GATEWAY:  'mcp-gateway',
  MCP_REGISTRY: 'mcp-registry',
  VIRTUAL_MCP:  'virtual-mcp',
  SMART_AGENTS: 'smart-agents',
  DISCOVERY:    'discovery',
  PLUGINS:      'plugins',
  SETTINGS:     'settings-up',
  // Group label that holds the page entries in the side menu.
  GROUP:        'Universal Proxy',
} as const;

export type PageType = typeof PAGE_TYPES[keyof typeof PAGE_TYPES];

// Route names are PRODUCT-prefixed (NOT `c-cluster-<product>-…`).
// Rancher's getProductFromRoute() regex (@rancher/shell utils/router.js)
// extracts the product slug from route names matching `^c-cluster-([^-]+)`,
// which captures only the first non-dash segment. With a dashed slug like
// `suse-ai-up`, the regex captures `suse` and Rancher errors with
// "Product suse not found". Putting the slug at the front makes the regex
// miss entirely so the lookup falls through to `meta.product`, which we
// set explicitly on every route. AIF uses the same pattern.
export const ROUTE_NAMES = {
  HOME:         `${PRODUCT}-c-cluster-${PAGE_TYPES.HOME}`,
  MCP_GATEWAY:  `${PRODUCT}-c-cluster-${PAGE_TYPES.MCP_GATEWAY}`,
  MCP_REGISTRY: `${PRODUCT}-c-cluster-${PAGE_TYPES.MCP_REGISTRY}`,
  VIRTUAL_MCP:  `${PRODUCT}-c-cluster-${PAGE_TYPES.VIRTUAL_MCP}`,
  SMART_AGENTS: `${PRODUCT}-c-cluster-${PAGE_TYPES.SMART_AGENTS}`,
  DISCOVERY:    `${PRODUCT}-c-cluster-${PAGE_TYPES.DISCOVERY}`,
  PLUGINS:      `${PRODUCT}-c-cluster-${PAGE_TYPES.PLUGINS}`,
  SETTINGS:     `${PRODUCT}-c-cluster-${PAGE_TYPES.SETTINGS}`,
} as const;

// Display + nav metadata for each page. Weights drive ordering in the
// side menu — higher weight = nearer the top. Big gaps (AIF style) leave
// room for future entries without re-balancing every line.
export interface PageDef {
  name:   string;
  label:  string;
  route:  string;
  weight: number;
}

export const PAGES: PageDef[] = [
  { name: PAGE_TYPES.HOME,         label: 'Home',         route: ROUTE_NAMES.HOME,         weight: 600 },
  { name: PAGE_TYPES.MCP_GATEWAY,  label: 'MCP Gateway',  route: ROUTE_NAMES.MCP_GATEWAY,  weight: 500 },
  { name: PAGE_TYPES.MCP_REGISTRY, label: 'MCP Registry', route: ROUTE_NAMES.MCP_REGISTRY, weight: 400 },
  { name: PAGE_TYPES.VIRTUAL_MCP,  label: 'Virtual MCP',  route: ROUTE_NAMES.VIRTUAL_MCP,  weight: 300 },
  { name: PAGE_TYPES.SMART_AGENTS, label: 'Smart Agents', route: ROUTE_NAMES.SMART_AGENTS, weight: 200 },
  { name: PAGE_TYPES.DISCOVERY,    label: 'Discovery',    route: ROUTE_NAMES.DISCOVERY,    weight: 150 },
  { name: PAGE_TYPES.PLUGINS,      label: 'Plugins',      route: ROUTE_NAMES.PLUGINS,      weight: 120 },
  { name: PAGE_TYPES.SETTINGS,     label: 'Settings',     route: ROUTE_NAMES.SETTINGS,     weight: 100 },
];
