/** Short, inert form of a SHA-256 value for tables. */
export function shortHash(hash: string): string {
  return `${hash.slice(0, 12)}…`;
}
