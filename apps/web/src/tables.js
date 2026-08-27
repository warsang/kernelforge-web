/**
 * Browser-side Vergilius table loading: fetch the JSON dumps Vite serves
 * from /public and register them into a StructTables instance. Avoids
 * node:fs so this package stays browser-native.
 */

const TYPES = [
  "_EPROCESS", "_ETHREAD", "_KPROCESS", "_KTHREAD", "_LIST_ENTRY",
  "_UNICODE_STRING", "_OBJECT_TYPE", "_OBJECT_HEADER", "_HANDLE_TABLE",
  "_PS_PROTECTION", "_KLDR_DATA_TABLE_ENTRY", "_LDR_DATA_TABLE_ENTRY",
  "_KPCR", "_KPRCB", "_MMVAD", "_MMVAD_SHORT",
];

export async function loadTables(fetchImpl = fetch, build = "windows-10/22h2") {
  const { StructTables } = await import("@kernelforge/ntsim/src/structs.mjs");
  const tables = new StructTables();
  await Promise.all(
    TYPES.map(async (name) => {
      try {
        const res = await fetchImpl(`/tables/${build}/${name}.json`);
        if (!res.ok) return; // type absent for this build
        const json = await res.json();
        tables.register(name, json.totalSize, Object.values(json.fieldsByName));
      } catch {
        /* optional type */
      }
    })
  );
  if (!tables.has("_EPROCESS")) throw new Error("failed to load _EPROCESS table");
  return tables;
}
