export interface SpecMeta {
  slug: string;
  name: string;
  vendor: string;
  category: string;
  language: string;
  status: string;
  version: string;
  source_repo: string;
  last_updated: string;
}

export function parseFrontmatter(raw: string): { meta: SpecMeta; content: string } {
  const normalized = raw.replace(/\r\n/g, '\n');
  const match = normalized.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!match) throw new Error('Invalid frontmatter');
  const meta: Record<string, string> = {};
  match[1].split('\n').forEach(line => {
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) return;
    const key = line.slice(0, colonIdx).trim();
    const val = line.slice(colonIdx + 1).trim().replace(/^["']|["']$/g, '');
    if (key) meta[key] = val;
  });
  return { meta: meta as unknown as SpecMeta, content: match[2] };
}

export const categoryLabels: Record<string, string> = {
  'cloud-infrastructure': 'Cloud Infrastructure',
  'identity-access-management': 'Identity & Access Management',
  'security-network-infrastructure': 'Security & Network Infrastructure',
  'vulnerability-application-security': 'Vulnerability & Application Security',
  'monitoring-logging-observability': 'Monitoring, Logging & Observability',
  'saas-collaboration': 'SaaS & Collaboration',
  'devops-developer-platforms': 'DevOps & Developer Platforms',
};

export const RAW_BASE = 'https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs';
