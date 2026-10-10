// Reproducible build for the FootprintX browser extension.
//   FOOTPRINTX_API_URL=https://api.example.com FOOTPRINTX_WEB_URL=https://app.example.com node build.mjs [--zip]
import { build } from 'esbuild';
import { cp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { zipSync } from 'fflate';

const root = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(root, 'dist');
const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
const apiUrl = new URL(process.env.FOOTPRINTX_API_URL ?? 'http://localhost:4000');
const webUrl = new URL(process.env.FOOTPRINTX_WEB_URL ?? 'http://localhost:5173');
if (process.env.NODE_ENV === 'production' && (apiUrl.protocol !== 'https:' || webUrl.protocol !== 'https:')) {
  throw new Error('Production extension builds require https API and web URLs');
}

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
await build({
  entryPoints: { background: 'src/background.ts', popup: 'src/popup.ts', warning: 'src/warning.ts' },
  outdir: dist,
  bundle: true,
  format: 'esm',
  target: 'chrome116',
  minify: false,
  sourcemap: false,
  absWorkingDir: root,
  define: { __API_BASE__: JSON.stringify(apiUrl.origin), __WEB_BASE__: JSON.stringify(webUrl.origin) },
  logLevel: 'warning',
});
await cp(path.join(root, 'static'), dist, { recursive: true, filter: (src) => !src.endsWith('manifest.template.json') });
const manifest = (await readFile(path.join(root, 'static/manifest.template.json'), 'utf8'))
  .replace('__VERSION__', pkg.version)
  .replace('__API_ORIGIN__', apiUrl.origin);
await writeFile(path.join(dist, 'manifest.json'), manifest);
console.log(`Built extension ${pkg.version} → dist/ (API ${apiUrl.origin}, web ${webUrl.origin})`);

if (process.argv.includes('--zip')) {
  const files = {};
  async function walk(dir) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) await walk(full);
      else files[path.relative(dist, full).split(path.sep).join('/')] = new Uint8Array(await readFile(full));
    }
  }
  await walk(dist);
  // Fixed timestamps make the archive reproducible.
  const zipped = zipSync(Object.fromEntries(Object.entries(files).sort().map(([k, v]) => [k, [v, { mtime: new Date('2026-01-01T00:00:00Z') }]])));
  await mkdir(path.join(root, 'packages'), { recursive: true });
  const out = path.join(root, 'packages', `footprintx-extension-${pkg.version}.zip`);
  await writeFile(out, zipped);
  console.log(`Packaged → ${path.relative(root, out)}`);
}
