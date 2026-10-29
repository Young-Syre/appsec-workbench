/**
 * The version, from one place.
 *
 * Read from package.json at build time would be nicer and would also mean the
 * published package depends on its own package.json being present at runtime,
 * which it is not when bundled. The CI workflow asserts this matches
 * package.json, so the duplication cannot drift.
 */
export const VERSION = '0.1.0';
