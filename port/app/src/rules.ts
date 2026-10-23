export interface Rule {
  id: string;
  app: string;
  action: 'allow' | 'deny';
  remote: string;
}

export function sortRules(rules: Rule[], field: keyof Rule, ascending: boolean = true): Rule[] {
  return [...rules].sort((a, b) => {
    if (a[field] < b[field]) return ascending ? -1 : 1;
    if (a[field] > b[field]) return ascending ? 1 : -1;
    return 0;
  });
}

export function filterRules(rules: Rule[], search: string): Rule[] {
  if (!search) return rules;
  const s = search.toLowerCase();
  return rules.filter(r =>
    r.app.toLowerCase().includes(s) ||
    r.remote.toLowerCase().includes(s) ||
    r.action.toLowerCase().includes(s)
  );
}
