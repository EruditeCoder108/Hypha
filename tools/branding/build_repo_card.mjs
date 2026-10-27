// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Native SVG template + PNG export. The existing approved logo is embedded intact.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const output = join(root, 'assets/readme');
const content = {
  name: 'Hypha',
  project: 'PROJECT RELAY',
  license: 'NON-COMMERCIAL',
  headline: ['Messages move.', 'Even offline.'],
  description: ['Private messages. No internet required.', 'Carried by nearby phones and fixed couriers.'],
  topics: 'ANDROID  /  BLE  /  WI-FI DIRECT  /  ESP32',
  repository: 'EruditeCoder108/Hypha',
};
const escape = value => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const logo = (await readFile(join(root, 'assets/images/hypha-app-icon.png'))).toString('base64');
const bg = '#fcfcfb';
const ink = '#16241f';
const muted = '#61766a';
const green = '#166c48';
const nodes = [[744, 214], [890, 196], [1039, 210], [1178, 253],
  [1175, 447], [1046, 479], [900, 471], [753, 426]];
const edges = [[0,1],[1,2],[2,3],[3,4],[4,5],[5,6],[6,7],[7,0],[1,6],[2,5],[0,2],[6,4]];
const constellation = edges.map(([a,b]) => `<path d="M${nodes[a].join(' ')}L${nodes[b].join(' ')}"/>`).join('\n');
const dots = nodes.map(([x,y]) => `<circle cx="${x}" cy="${y}" r="3.5"/>`).join('\n');
const svg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="1280" height="640" viewBox="0 0 1280 640" role="img" aria-labelledby="title desc">
<title id="title">${escape(content.name)} — private messages without the internet</title>
<desc id="desc">A repository social card with the approved Hypha mark and a conceptual sender, courier, and recipient network. No device or contact data. All important content has at least an 80 pixel safe inset.</desc>
<defs>
  <radialGradient id="mint-wash"><stop offset="0" stop-color="#dff2e6" stop-opacity=".85"/><stop offset="1" stop-color="${bg}" stop-opacity="0"/></radialGradient>
</defs>
<rect width="1280" height="640" fill="${bg}"/>
<circle cx="975" cy="331" r="263" fill="url(#mint-wash)"/>
<g font-family="Segoe UI,DejaVu Sans,Arial,sans-serif">
  <g id="brand">
    <image x="80" y="80" width="96" height="96" xlink:href="data:image/png;base64,${logo}"/>
    <text id="project-name" x="200" y="150" fill="${ink}" font-size="64" font-weight="600" letter-spacing="-2">${escape(content.name)}</text>
    <text id="project-label" x="1200" y="111" text-anchor="end" fill="${muted}" font-size="14" font-weight="600" letter-spacing="2">${escape(content.project)}</text>
    <rect x="1001" y="128" width="199" height="29" rx="14.5" fill="#e5f1e9"/>
    <text id="license" x="1100.5" y="147" text-anchor="middle" fill="${green}" font-size="12" font-weight="600" letter-spacing="1">${escape(content.license)}</text>
  </g>
  <path d="M80 188H1200" stroke="#dce5de"/>
  <g id="headline" fill="${ink}" font-size="74" font-weight="600" letter-spacing="-2.2">
    <text x="80" y="293">${escape(content.headline[0])}</text>
    <text x="80" y="377">${escape(content.headline[1])}</text>
  </g>
  <g id="description" fill="${muted}" font-size="21">
    <text x="84" y="431">${escape(content.description[0])}</text>
    <text x="84" y="463">${escape(content.description[1])}</text>
  </g>
  <g id="network-illustration">
    <g stroke="#d4e4d9" fill="none" stroke-width="1.2">${constellation}
      <path d="M744 214L804 356L753 426M890 196L968 276L900 471M1039 210L1130 356L1175 447"/>
    </g>
    <g fill="#a6c1af">${dots}</g>
    <path d="M804 356C870 356 886 276 968 276S1072 356 1130 356" fill="none" stroke="#4b8b68" stroke-width="3"/>
    <g fill="${bg}" stroke="#b8d3c2">
      <circle cx="804" cy="356" r="26"/><circle cx="968" cy="276" r="31"/><circle cx="1130" cy="356" r="26"/>
    </g>
    <g fill="${ink}"><circle cx="804" cy="356" r="14"/><circle cx="1130" cy="356" r="14"/></g>
    <circle cx="968" cy="276" r="18" fill="${green}"/>
    <g fill="${bg}"><circle cx="804" cy="356" r="3"/><circle cx="968" cy="276" r="4"/><circle cx="1130" cy="356" r="3"/></g>
    <circle cx="898" cy="314" r="19" fill="${bg}"/>
    <rect x="885" y="304" width="26" height="20" rx="4" fill="#a7e7c1" stroke="${green}"/>
    <path d="M889 309L898 315L907 309" fill="none" stroke="${green}" stroke-width="1.5"/>
    <g fill="${muted}" font-size="12" font-weight="600" text-anchor="middle" letter-spacing="1.2">
      <text x="804" y="403">SENDER</text><text x="968" y="231">COURIER</text><text x="1130" y="403">RECIPIENT</text>
    </g>
    <rect x="869" y="433" width="198" height="33" rx="16.5" fill="#e4f2e8"/>
    <text x="968" y="455" text-anchor="middle" fill="${green}" font-size="13">Recipient-encrypted envelope</text>
  </g>
  <path d="M80 516H1200" stroke="#dce5de"/>
  <text id="topics" x="80" y="554" fill="${green}" font-size="13" font-weight="600" letter-spacing=".65">${escape(content.topics)}</text>
  <text id="repository" x="1200" y="554" text-anchor="end" fill="${muted}" font-size="14">${escape(content.repository)}</text>
  <!-- Toggle display to inline when editing; never include these guides in the upload. -->
  <g id="safe-area-guides" display="none" fill="none" stroke="#b42332" stroke-dasharray="8 6">
    <rect x="80" y="80" width="1120" height="480"/>
  </g>
</g>
</svg>\n`;
await mkdir(output, { recursive: true });
await writeFile(join(output, 'repo-card-template.svg'), svg);
if (process.argv.includes('--svg-only')) {
  console.log('Created assets/readme/repo-card-template.svg');
} else {
  let sharp;
  try { sharp = createRequire(import.meta.url)('sharp'); }
  catch {
    if (!process.env.HYPHA_GRAPHICS_NODE_MODULES) {
      throw new Error('SVG created. Install sharp or set HYPHA_GRAPHICS_NODE_MODULES to a node_modules directory containing sharp; --svg-only needs no renderer.');
    }
    sharp = createRequire(join(resolve(process.env.HYPHA_GRAPHICS_NODE_MODULES), 'package.json'))('sharp');
  }
  await sharp(Buffer.from(svg)).png({ compressionLevel: 9 }).toFile(join(output, 'repo-card.png'));
  const metadata = await sharp(join(output, 'repo-card.png')).metadata();
  const bytes = (await readFile(join(output, 'repo-card.png'))).length;
  if (metadata.width !== 1280 || metadata.height !== 640 || bytes >= 1_000_000) {
    throw new Error('Social preview dimensions or size exceed the intended GitHub upload bounds');
  }
  console.log(JSON.stringify({png:'assets/readme/repo-card.png',svg:'assets/readme/repo-card-template.svg',width:metadata.width,height:metadata.height,bytes,safeInset:80}));
}
