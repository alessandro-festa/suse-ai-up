import { PRODUCT, PAGE_TYPES, ROUTE_NAMES } from './config/product';

export default [
  {
    name:     `c-cluster-${PRODUCT}-root`,
    path:     `/c/:cluster/${PRODUCT}`,
    redirect: { name: ROUTE_NAMES.HOME },
    meta:     { product: PRODUCT },
  },
  {
    name:      ROUTE_NAMES.HOME,
    path:      `/c/:cluster/${PRODUCT}/${PAGE_TYPES.HOME}`,
    component: () => import('./pages/Home.vue'),
    meta:      { product: PRODUCT, category: PAGE_TYPES.HOME },
  },
  {
    name:      ROUTE_NAMES.MCP_GATEWAY,
    path:      `/c/:cluster/${PRODUCT}/${PAGE_TYPES.MCP_GATEWAY}`,
    component: () => import('./pages/MCPGateway.vue'),
    meta:      { product: PRODUCT, category: PAGE_TYPES.MCP_GATEWAY },
  },
  {
    name:      ROUTE_NAMES.MCP_REGISTRY,
    path:      `/c/:cluster/${PRODUCT}/${PAGE_TYPES.MCP_REGISTRY}`,
    component: () => import('./pages/MCPRegistry.vue'),
    meta:      { product: PRODUCT, category: PAGE_TYPES.MCP_REGISTRY },
  },
  {
    name:      ROUTE_NAMES.VIRTUAL_MCP,
    path:      `/c/:cluster/${PRODUCT}/${PAGE_TYPES.VIRTUAL_MCP}`,
    component: () => import('./pages/VirtualMCP.vue'),
    meta:      { product: PRODUCT, category: PAGE_TYPES.VIRTUAL_MCP },
  },
  {
    name:      ROUTE_NAMES.SMART_AGENTS,
    path:      `/c/:cluster/${PRODUCT}/${PAGE_TYPES.SMART_AGENTS}`,
    component: () => import('./pages/SmartAgents.vue'),
    meta:      { product: PRODUCT, category: PAGE_TYPES.SMART_AGENTS },
  },
  {
    name:      ROUTE_NAMES.SETTINGS,
    path:      `/c/:cluster/${PRODUCT}/${PAGE_TYPES.SETTINGS}`,
    component: () => import('./pages/Settings.vue'),
    meta:      { product: PRODUCT, category: PAGE_TYPES.SETTINGS },
  },
];
