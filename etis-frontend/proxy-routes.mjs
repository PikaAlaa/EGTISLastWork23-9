// Explicit API allowlist for the same-origin proxy (design core-v1 §6).
// The four original routes keep their previous behaviour (any method is forwarded and
// the backend answers). SOC console routes are listed with their exact methods.
const LEGACY = new Set(['/api/analyze', '/api/threats', '/api/stats', '/api/health/ready']);
const ROUTES = [
  [/^\/api\/incidents$/, ['GET']],
  [/^\/api\/incidents\/\d{1,10}$/, ['GET', 'PATCH']],
  [/^\/api\/incidents\/\d{1,10}\/merge$/, ['POST']],
  [/^\/api\/campaigns$/, ['GET', 'POST']],
  [/^\/api\/campaigns\/suggestions$/, ['GET']],
  [/^\/api\/campaigns\/\d{1,10}\/incidents$/, ['POST']],
  [/^\/api\/indicators$/, ['GET']],
  [/^\/api\/indicators\/\d{1,10}$/, ['GET']],
  [/^\/api\/community-reports$/, ['GET']],
  [/^\/api\/community-reports\/\d{1,10}$/, ['PATCH']],
  [/^\/api\/attack\/techniques$/, ['GET']],
  [/^\/api\/attack\/techniques\/T\d{4}(?:\.\d{3})?$/, ['GET']],
  [/^\/api\/attack\/coverage$/, ['GET']],
  // Malware file scans (design malware-engine-v1 §6.8): read-only; scans start only from the local command.
  [/^\/api\/malware\/scans$/, ['GET']],
  [/^\/api\/malware\/scans\/\d{1,10}$/, ['GET']],
  [/^\/api\/malware\/health$/, ['GET']],
  // network.windows imports (design network-windows-v1 §6.7): read-only; imports start only from the local command.
  [/^\/api\/network\/windows\/imports$/, ['GET']],
  [/^\/api\/network\/windows\/imports\/\d{1,10}$/, ['GET']],
  [/^\/api\/network\/windows\/health$/, ['GET']],
];

// Returns 'allowed', 'method_not_allowed' or 'not_found'.
export function routeDecision(pathname, method) {
  if (LEGACY.has(pathname)) return 'allowed';
  const route = ROUTES.find(([pattern]) => pattern.test(pathname));
  if (!route) return 'not_found';
  return route[1].includes(method) ? 'allowed' : 'method_not_allowed';
}

export const BODY_METHODS = new Set(['POST', 'PATCH']);
export const SPA_PATHS = new Set(['/', '/scan', '/threats', '/stats', '/incidents', '/indicators', '/attack', '/files', '/network']);
