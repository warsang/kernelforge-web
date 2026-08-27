/**
 * sogen-targets.js — registry of student-uploaded target binaries for the
 * vendored sogen WASM core. Bytes stay in memory (never persisted server-
 * side); the wasm client seeds them into the emulator's IDBFS root via the
 * worker's writeFile message before callMain.
 */

const targets = [];

export function addSogenTarget(name, bytes) {
  targets.unshift({ name: String(name), bytes, at: Date.now() });
  if (targets.length > 4) targets.length = 4;
  return targets[0];
}

export function latestSogenTarget() {
  return targets[0] ?? null;
}

export function listSogenTargets() {
  return [...targets];
}
