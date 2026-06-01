// Shared registry-entry enrichment. Both MCPRegistry (catalog) and
// MCPGateway (adapter create picker) project the raw backend payload
// into the same shape so cards look identical and runtime/transport
// classification stays in one place.

import { MCPServer } from './registry';

export type RuntimeTone = 'info' | 'success' | 'warning' | 'error' | 'neutral';

export interface SecretField {
  env:       string;
  name:      string;
  type:      'text' | 'secret' | 'bool';
  example:   string;
  templated: boolean;
}

export interface RegistryView {
  id:          string;
  title:       string;
  initials:    string;
  description: string;
  version:     string;
  iconUrl:     string;
  runtime:     { label: string; tone: RuntimeTone; identifier: string };
  transport:   string;
  category:    string;
  tags:        string[];
  sourceUrl:   string;
  secrets:     SecretField[];
  raw:         MCPServer;
}

export function safeMeta(e: MCPServer): any {
  return ((e as any)._meta || (e as any).meta || {}) as Record<string, any>;
}

function asString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

export function classifyRuntime(e: MCPServer): { label: string; tone: RuntimeTone; identifier: string } {
  const meta    = safeMeta(e);
  const cmdType = String(meta?.sidecarConfig?.commandType || '').toLowerCase();
  const pkgs    = Array.isArray((e as any).packages) ? (e as any).packages : [];
  const firstPkg: any = pkgs[0] || {};
  const identifier = asString(firstPkg.identifier) || asString((e as any).image);

  const map: Record<string, { label: string; tone: RuntimeTone }> = {
    docker:      { label: 'Container', tone: 'info' },
    podman:      { label: 'Container', tone: 'info' },
    oci:         { label: 'Container', tone: 'info' },
    npx:         { label: 'Node.js',   tone: 'success' },
    node:        { label: 'Node.js',   tone: 'success' },
    npm:         { label: 'Node.js',   tone: 'success' },
    pip:         { label: 'Python',    tone: 'warning' },
    pipx:        { label: 'Python',    tone: 'warning' },
    python:      { label: 'Python',    tone: 'warning' },
    uvx:         { label: 'Python',    tone: 'warning' },
    pypi:        { label: 'Python',    tone: 'warning' },
    go:          { label: 'Go',        tone: 'info' },
    gomod:       { label: 'Go',        tone: 'info' },
    cargo:       { label: 'Rust',      tone: 'warning' },
    'crates.io': { label: 'Rust',      tone: 'warning' },
    maven:       { label: 'Java',      tone: 'info' },
    binary:      { label: 'Binary',    tone: 'neutral' },
  };

  if (cmdType && map[cmdType]) return { ...map[cmdType], identifier };
  const regType = String(firstPkg.registryType || '').toLowerCase();
  if (regType && map[regType]) return { ...map[regType], identifier };

  if (/^(docker\.io|ghcr\.io|quay\.io|gcr\.io|mcr\.microsoft\.com|registry\.)/i.test(identifier)) {
    return { label: 'Container', tone: 'info', identifier };
  }
  if (identifier) return { label: 'Binary', tone: 'neutral', identifier };
  return { label: 'Unknown', tone: 'neutral', identifier: '' };
}

function normalizeSecretType(t: unknown): 'text' | 'secret' | 'bool' {
  const v = String(t || '').toLowerCase();
  if (v === 'secret' || v === 'password') return 'secret';
  if (v === 'bool' || v === 'boolean') return 'bool';
  return 'text';
}

export function extractSecrets(e: MCPServer): SecretField[] {
  const meta    = safeMeta(e);
  const secrets = meta?.config?.secrets;
  if (!Array.isArray(secrets)) return [];
  return secrets
    .map((s: any) => {
      const env = asString(s?.env);
      if (!env) return null;
      return {
        env,
        name:      asString(s?.name) || env,
        type:      normalizeSecretType(s?.type),
        example:   asString(s?.example),
        templated: !!s?.templated,
      } as SecretField;
    })
    .filter(Boolean) as SecretField[];
}

export function toRegistryView(e: MCPServer): RegistryView {
  const meta  = safeMeta(e);
  const about = meta?.about || {};
  const id    = asString(e.id) || asString(e.name) || '(unnamed)';
  const title = asString(about.title) || asString(e.name) || id;

  return {
    id,
    title,
    initials:    (title.match(/[A-Za-z0-9]/g) || []).slice(0, 2).join('').toUpperCase() || '?',
    description: asString(about.description) || asString(e.description) || '',
    version:     asString(e.version),
    iconUrl:     asString(about.icon),
    runtime:     classifyRuntime(e),
    transport:   asString((Array.isArray((e as any).packages) ? (e as any).packages : [])[0]?.transport?.type),
    category:    asString(meta?.category),
    tags:        Array.isArray(meta?.tags)
      ? meta.tags.filter((t: any) => typeof t === 'string').slice(0, 6)
      : [],
    sourceUrl:   asString(meta?.source?.project) || asString((e as any).url),
    secrets:     extractSecrets(e),
    raw:         e,
  };
}

// Free-text search across the surface fields a card displays.
export function matchesQuery(v: RegistryView, q: string): boolean {
  if (!q) return true;
  const needle = q.toLowerCase();
  if (v.id.toLowerCase().includes(needle)) return true;
  if (v.title.toLowerCase().includes(needle)) return true;
  if (v.description.toLowerCase().includes(needle)) return true;
  if (v.category.toLowerCase().includes(needle)) return true;
  if (v.runtime.label.toLowerCase().includes(needle)) return true;
  if (v.tags.some((t) => t.toLowerCase().includes(needle))) return true;
  return false;
}
