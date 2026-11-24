/** Roles that hold the backend write permission for detections and incidents. */
const WRITE_ROLES = new Set(['analyst', 'hunter', 'engineer', 'admin'])

export function canWrite(role: string | undefined): boolean {
  return role !== undefined && WRITE_ROLES.has(role)
}

/** Roles with the rules:read permission (see backend core/rbac.py). */
const RULE_READ_ROLES = new Set(['hunter', 'engineer', 'admin'])

export function canReadRules(role: string | undefined): boolean {
  return role !== undefined && RULE_READ_ROLES.has(role)
}

/** Roles with the connectors:read and connectors:write permissions. */
const SOURCE_ROLES = new Set(['engineer', 'admin'])

export function canManageSources(role: string | undefined): boolean {
  return role !== undefined && SOURCE_ROLES.has(role)
}
