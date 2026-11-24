/** Roles that hold the backend write permission for detections and incidents. */
const WRITE_ROLES = new Set(['analyst', 'hunter', 'engineer', 'admin'])

export function canWrite(role: string | undefined): boolean {
  return role !== undefined && WRITE_ROLES.has(role)
}
