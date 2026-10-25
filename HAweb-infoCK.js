#!/usr/bin/env node
/*
 * HAweb-infoCK - Outil de reconnaissance web pour CTF
 * 100% Node.js natif, aucune dépendance à installer.
 * Lancement : node HAweb-infoCK.js [cible] [--full]
 */

import dns from 'dns/promises';
import net from 'net';
import tls from 'tls';
import readline from 'readline';
import fs from 'fs';
import { URL } from 'url';

// ============ COULEURS ANSI (boutons terminal) ============
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgBlue: '\x1b[44m',
  bgGreen: '\x1b[42m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
};

const ok = (t) => `${C.green}✔ ${t}${C.reset}`;
const ko = (t) => `${C.red}✘ ${t}${C.reset}`;
const info = (t) => `${C.cyan}➜ ${t}${C.reset}`;
const warn = (t) => `${C.yellow}⚠ ${t}${C.reset}`;

let TARGET = process.argv[2] && !process.argv[2].startsWith('-') ? cleanTarget(process.argv[2]) : '';
let LOG = []; // pour export rapport

function log(line = '') { LOG.push(line.replace(/\x1b\[[0-9;]*m/g, '')); }
function out(line = '') { console.log(line); log(line); }
function section(title) {
  const bar = '═'.repeat(Math.max(10, 60 - title.length));
  out(`\n${C.bold}${C.cyan}╔══ ${title} ${bar}${C.reset}`);
}

// Nettoie "https://example.com/page" -> "example.com"
function cleanTarget(t) {
  if (!t) return '';
  t = t.trim().toLowerCase();
  t = t.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].split('?')[0];
  t = t.replace(/\/$/, '');
  return t;
}
function baseUrl() {
  return `http://${TARGET}`;
}
async function fetchSmart(path, opts = {}) {
  // essaie https puis http
  const tries = [`https://${TARGET}${path}`, `http://${TARGET}${path}`];
  for (const u of tries) {
    try {
      const ctrl = new AbortController();
      const to = setTimeout(() => ctrl.abort(), opts.timeout || 10000);
      const r = await fetch(u, {
        signal: ctrl.signal,
        redirect: 'follow',
        headers: { 'User-Agent': 'HAweb-infoCK/1.0 (CTF recon)', Accept: 'text/html,application/xhtml+xml,*/*' },
      });
      clearTimeout(to);
      const text = opts.text === false ? '' : await r.text().catch(() => '');
      return { url: u, status: r.status, headers: r.headers, body: text.slice(0, 200000), finalUrl: r.url };
    } catch { /* essaie suivant */ }
  }
  return null;
}

// ============ 1. IP + HEBERGEUR + GEO ============
async function modIP() {
  section(`IP / HÉBERGEUR / GÉO — ${TARGET}`);
  try {
    const a = await dns.resolve4(TARGET).catch(() => []);
    const aaaa = await dns.resolve6(TARGET).catch(() => []);
    out(`${info('IPv4 :')} ${a.join(', ') || 'introuvable'}`);
    out(`${info('IPv6 :')} ${aaaa.join(', ') || '—'}`);
    const ip = a[0];
    if (!ip) { out(warn('Pas d\'IP, suite impossible pour la géo.')); return { ip: null }; }
    // reverse DNS
    try {
      const rev = await dns.reverse(ip);
      out(`${info('Reverse DNS :')} ${rev.join(', ')}`);
    } catch { out(`${info('Reverse DNS :')} aucun`); }
    // Hébergeur + géo via ip-api (gratuit, sans clé)
    try {
      const r = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting,query`);
      const j = await r.json();
      if (j.status === 'success') {
        out(`${info('Hébergeur / ISP :')} ${C.bold}${j.isp}${C.reset}`);
        out(`${info('Organisation  :')} ${j.org}`);
        out(`${info('AS            :')} ${j.as}`);
        out(`${info('Pays          :')} ${j.country} (${j.countryCode}) - ${j.regionName}, ${j.city} ${j.zip || ''}`);
        out(`${info('Coords        :')} ${j.lat}, ${j.lon}  | TZ: ${j.timezone}`);
        out(`${info('Hosting?      :')} ${j.hosting ? C.yellow + 'OUI (datacenter/cloud)' + C.reset : 'non (a priori FAI/box)'}`);
        out(`${info('Proxy?        :')} ${j.proxy ? 'oui' : 'non'}  | Mobile: ${j.mobile ? 'oui' : 'non'}`);
      } else out(warn('ip-api: échec'));
    } catch (e) { out(warn('Géo ip-api injoignable (hors-ligne ?) : ' + e.message)); }
    return { ip };
  } catch (e) { out(ko(e.message)); return {}; }
}

// ============ 2. DNS COMPLET ============
async function modDNS() {
  section(`DNS — ${TARGET}`);
  const types = [
    ['A', () => dns.resolve4(TARGET)],
    ['AAAA', () => dns.resolve6(TARGET)],
    ['CNAME', () => dns.resolveCname(TARGET)],
    ['MX', () => dns.resolveMx(TARGET)],
    ['NS', () => dns.resolveNs(TARGET)],
    ['TXT', () => dns.resolveTxt(TARGET)],
    ['SOA', () => dns.resolveSoa(TARGET)],
    ['SRV', () => dns.resolveSrv(`_http._tcp.${TARGET}`)],
  ];
  for (const [name, fn] of types) {
    try {
      const v = await fn();
      const txt = name === 'TXT' ? v.map(x => x.join('')).join('\n      ') : JSON.stringify(v);
      out(`${ok(name.padEnd(6))} ${txt}`);
      if (name === 'TXT') {
        const all = v.map(x => x.join('')).join(' ');
        if (/v=spf1/i.test(all)) out(`   ${C.yellow}→ SPF détecté${C.reset}`);
        if (/v=DMARC/i.test(all)) out(`   ${C.yellow}→ DMARC détecté${C.reset}`);
      }
    } catch { out(`${ko(name.padEnd(6))} aucun enregistrement`); }
  }
  // DMARC _dmarc + DKIM selector commun
  for (const sub of [`_dmarc.${TARGET}`, `_domainkey.${TARGET}`]) {
    try { const v = await dns.resolveTxt(sub); out(`${ok(sub)} ${v.map(x => x.join('')).join(' | ')}`); }
    catch { out(`${info(sub + ' :')} —`); }
  }
  // Zone transfer ? (souvent refusé mais testé en CTF)
  try {
    const ns = await dns.resolveNs(TARGET).catch(() => []);
    out(`\n${info('Serveurs NS : ' + (ns.join(', ') || 'inconnus'))}`);
    out(C.dim + '(Transfert de zone AXFR : à tester à la main avec dig/host si NS le permet — souvent la faille CTF)' + C.reset);
  } catch {}
}

// ============ 3. WHOIS ============
function whoisQuery(server, query) {
  return new Promise((resolve) => {
    const s = net.createConnection(43, server, () => s.write(query + '\r\n'));
    let data = '';
    s.on('data', d => { data += d.toString(); });
    s.on('error', () => resolve(''));
    setTimeout(() => { try { s.destroy(); } catch {} resolve(data); }, 8000);
    s.on('close', () => resolve(data));
  });
}
async function modWhois() {
  section(`WHOIS — ${TARGET}`);
  const tld = TARGET.split('.').pop();
  const servers = { com: 'whois.verisign-grs.com', net: 'whois.verisign-grs.com', fr: 'whois.afnic.fr', io: 'whois.nic.io', org: 'whois.pir.org', eu: 'whois.eu', be: 'whois.dns.be', ch: 'whois.nic.ch' };
  const srv = servers[tld] || 'whois.iana.org';
  out(info(`Serveur : ${srv}`));
  let raw = await whoisQuery(srv, TARGET);
  if (!raw) raw = await whoisQuery('whois.iana.org', TARGET);
  if (!raw) { out(ko('WHOIS injoignable')); return; }
  // Si réponse IANA -> suit le refer
  const m = raw.match(/whois:\s*(\S+)/i) || raw.match(/refer:\s*(\S+)/i);
  if (m && srv === 'whois.iana.org') {
    out(info(`Redirection vers ${m[1]}`));
    raw = await whoisQuery(m[1], TARGET);
  }
  const keep = raw.split('\n').filter(l => {
    const L = l.toLowerCase();
    return /registrar|registrant|creation|created|expir|updated|name server|nserver|status|holder|contact|org-|address|email/i.test(l) && !/^\s*>>>/.test(l);
  }).slice(0, 40);
  out((keep.length ? keep : raw.split('\n').slice(0, 40)).join('\n'));
  // Emails / noms intéressants pour CTF (OSINT)
  const emails = [...new Set(raw.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}/g) || [])].slice(0, 10);
  if (emails.length) out(`\n${C.yellow}✉ Emails trouvés :${C.reset} ${emails.join(', ')}`);
  log(raw.slice(0, 3000));
}

// ============ 4. HEADERS + TECHNOS ============
async function modHeaders() {
  section(`HEADERS HTTP + TECHNOS — ${TARGET}`);
  const r = await fetchSmart('/');
  if (!r) { out(ko('Site injoignable (http+https)')); return; }
  out(`${info('URL finale :')} ${r.finalUrl}  [${r.status}]`);
  const h = Object.fromEntries(r.headers.entries());
  const show = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator', 'set-cookie', 'content-type', 'location', 'x-frame-options', 'content-security-policy', 'strict-transport-security', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];
  for (const k of Object.keys(h)) if (!show.includes(k)) show.push(k);
  for (const k of show) if (h[k]) {
    const hot = /server|powered|generator|asp|php/i.test(k) ? C.yellow : '';
    out(`  ${C.bold}${k}${C.reset} : ${hot}${String(h[k]).slice(0, 300)}${C.reset}`);
  }
  // Cookies sans flags ?
  const cookies = r.headers.getSetCookie ? r.headers.getSetCookie() : (h['set-cookie'] ? [h['set-cookie']] : []);
  if (cookies.length) {
    out('');
    for (const c of cookies) {
      const flags = [];
      if (!/httponly/i.test(c)) flags.push(C.red + 'manque HttpOnly' + C.reset);
      if (!/secure/i.test(c)) flags.push(C.red + 'manque Secure' + C.reset);
      if (!/samesite/i.test(c)) flags.push(C.yellow + 'manque SameSite' + C.reset);
      out(`  🍪 ${c.slice(0, 150)} ${flags.length ? '→ ' + flags.join(', ') : C.green + 'flags OK' + C.reset}`);
    }
  }
  // Sécurité headers manquants
  const missing = [];
  if (!h['x-frame-options'] && !/frame-ancestors/.test(h['content-security-policy'] || '')) missing.push('X-Frame-Options (clickjacking?)');
  if (!h['content-security-policy']) missing.push('CSP');
  if (!h['strict-transport-security']) missing.push('HSTS');
  if (!h['x-content-type-options']) missing.push('X-Content-Type-Options');
  if (missing.length) out(`\n${warn('Headers sécurité manquants : ' + missing.join(' | '))}`);
  else out(`\n${ok('Headers sécurité présents')}`);
  // Fingerprint technos
  const fp = [];
  const b = r.body;
  const has = (re) => re.test(b) || Object.values(h).join(' ').match(re);
  if (has(/wp-content|wp-includes|wp-json/i)) fp.push('WordPress');
  if (has(/drupal/i)) fp.push('Drupal');
  if (has(/joomla/i)) fp.push('Joomla');
  if (has(/_next\/static/i)) fp.push('Next.js');
  if (has(/nuxt/i)) fp.push('Nuxt');
  if (has(/laravel/i)) fp.push('Laravel');
  if (has(/django|csrfmiddlewaretoken/i)) fp.push('Django');
  if (has(/rails|ruby/i)) fp.push('Rails');
  if (has(/php/i)) fp.push('PHP');
  if (has(/asp\.net|viewstate/i)) fp.push('ASP.NET');
  if (has(/cloudflare/i)) fp.push('Cloudflare (WAF/CDN)');
  if (has(/akamai/i)) fp.push('Akamai');
  if (has(/fastly/i)) fp.push('Fastly');
  if (has(/shopify/i)) fp.push('Shopify');
  if (has(/angular/i)) fp.push('Angular');
  if (has(/react/i)) fp.push('React');
  if (has(/vue/i)) fp.push('Vue.js');
  const title = (b.match(/<title>(.*?)<\/title>/is) || [])[1];
  const gen = (b.match(/<meta name=["']generator["'] content=["'](.*?)["']/i) || [])[1];
  if (title) out(`${info('Title :')} ${title.trim().slice(0, 120)}`);
  if (gen) out(`${info('Generator :')} ${gen}`);
  out(`${info('Technos probables :')} ${fp.length ? C.bold + fp.join(', ') + C.reset : 'non identifiées'}`);
  // Méthodes HTTP + redirections http->https ?
  try {
    const ctrl = new AbortController(); const to = setTimeout(() => ctrl.abort(), 6000);
    const o = await fetch(`http://${TARGET}/`, { method: 'OPTIONS', signal: ctrl.signal }).catch(() => null);
    clearTimeout(to);
    if (o) out(`${info('OPTIONS Allow :')} ${o.headers.get('allow') || '(vide)'}`);
  } catch {}
}

// ============ 5. ROBOTS / SITEMAP / SECURITY ============
async function modFiles() {
  section(`ROBOTS / SITEMAP / SECURITY — ${TARGET}`);
  for (const p of ['/robots.txt', '/sitemap.xml', '/sitemap_index.xml', '/.well-known/security.txt', '/security.txt', '/humans.txt', '/crossdomain.xml', '/.well-known/change-password']) {
    const r = await fetchSmart(p, { timeout: 8000 });
    if (r && r.status === 200 && r.body.length > 5 && r.body.length < 100000) {
      out(`\n${ok(p + ` [${r.status}] (${r.body.length} octets)`)}`);
      out(C.dim + r.body.slice(0, 1500) + C.reset);
      // Extrait sitemap -> URLs
      if (/sitemap/i.test(p)) {
        const urls = [...r.body.matchAll(/<loc>(.*?)<\/loc>/g)].map(m => m[1]).slice(0, 20);
        if (urls.length) out(`${info('URLs sitemap :')}\n  - ` + urls.join('\n  - '));
      }
      // robots -> Disallow intéressants
      if (/robots/.test(p)) {
        const dis = [...r.body.matchAll(/Disallow:\s*(\S+)/g)].map(m => m[1]).slice(0, 30);
        if (dis.length) out(`${C.yellow}→ À tester en priorité (Disallow) : ${dis.join(', ')}${C.reset}`);
      }
    } else out(`${ko(p)} ${r ? '[' + r.status + ']' : '(introuvable)'}`);
  }
}

// ============ 6. CRAWLER PAGES ============
function extractLinks(html, base) {
  const links = new Set();
  const re = /(?:href|src|action)=["'](.*?)["']/gi;
  let m;
  while ((m = re.exec(html))) {
    let u = m[1].trim();
    if (!u || u.startsWith('#') || u.startsWith('mailto:') || u.startsWith('tel:') || u.startsWith('javascript:') || u.startsWith('data:')) continue;
    try {
      const abs = new URL(u, base);
      if (abs.hostname.replace(/^www\./, '') === TARGET.replace(/^www\./, '')) {
        abs.hash = '';
        if (/\.(png|jpg|jpeg|gif|svg|ico|css|woff2?|ttf|eot)$/i.test(abs.pathname)) continue;
        links.add(abs.pathname + abs.search);
      }
    } catch {}
  }
  return [...links];
}
async function modCrawl() {
  section(`CRAWLER — toutes les pages — ${TARGET}`);
  const seen = new Set(['/']);
  const queue = ['/'];
  const found = [];
  out(info('Crawl BFS, max 60 pages, même domaine…'));
  while (queue.length && seen.size <= 60) {
    const path = queue.shift();
    const r = await fetchSmart(path, { timeout: 8000 });
    if (!r) continue;
    const type = r.headers.get('content-type') || '';
    found.push({ path, status: r.status, size: r.body.length, type });
    out(`  [${r.status}] ${path} (${r.body.length} o)`);
    if (type.includes('html')) {
      for (const l of extractLinks(r.body, r.finalUrl || `https://${TARGET}${path}`)) {
        if (!seen.has(l) && seen.size + queue.length < 60) { seen.add(l); queue.push(l); }
      }
    }
  }
  out(`\n${ok(`${found.length} pages cartographiées`)}`);
  // Pages intéressantes pour CTF
  const hot = found.filter(f => /admin|login|config|backup|old|test|dev|api|debug|phpinfo|\.bak|\.old|\.zip|\.git|wp-|\.env/i.test(f.path));
  if (hot.length) out(`${C.yellow}★ Pages sensibles détectées :${C.reset}\n  - ` + hot.map(f => `[${f.status}] ${f.path}`).join('\n  - '));
  return found;
}

// ============ 7. SOUS-DOMAINES ============
async function modSubdomains() {
  section(`SOUS-DOMAINES — ${TARGET}`);
  const subs = new Set();
  // a) crt.sh (transparence certificats)
  try {
    out(info('Interrogation crt.sh…'));
    const ctrl = new AbortController(); const to = setTimeout(() => ctrl.abort(), 12000);
    const r = await fetch(`https://crt.sh/?q=%25.${TARGET}&output=json`, { signal: ctrl.signal, headers: { 'User-Agent': 'HAweb-infoCK' } });
    clearTimeout(to);
    const j = await r.json();
    for (const e of j) for (const n of String(e.name_value).split('\n')) {
      n.trim().toLowerCase().endsWith(TARGET.toLowerCase()) && subs.add(n.trim().toLowerCase());
    }
    out(ok(`crt.sh : ${subs.size} sous-domaines`));
  } catch { out(warn('crt.sh injoignable')); }
  // b) bruteforce petite wordlist
  const WL = ['www', 'mail', 'ftp', 'admin', 'blog', 'api', 'dev', 'test', 'staging', 'beta', 'portal', 'vpn', 'webmail', 'shop', 'forum', 'support', 'docs', 'cdn', 'static', 'm', 'mobile', 'app', 'dashboard', 'panel', 'cpanel', 'webdisk', 'ns1', 'ns2', 'mx', 'smtp', 'imap', 'pop', 'owa', 'exchange', 'intranet', 'extranet', 'secure', 'dienst', 'demo', 'old', 'new', 'vps', 'server', 'host', 'cloud', 'git', 'jenkins', 'jira', 'confluence', 'grafana', 'kibana', 'db', 'mysql', 'postgres', 'redis', 'internal', 'prod', 'preprod', 'qa', 'sandbox', 'cdn1', 'images', 'assets', 'media', 'video', 'status', 'monitor', 'nagios', 'zabbix', 'ldap', 'sso', 'auth', 'login', 'register', 'pay', 'billing', 'crm', 'erp', 'hr', 'wiki', 'help', 'faq', 'contact', 'news', 'events', 'careers', 'jobs', 'fr', 'en', 'es', 'de', 'api-v1', 'api-v2', 'graphql', 'rest', 'soap', 'ws', 'socket', 'mqtt', 'proxy', 'gateway', 'firewall', 'router', 'switch', 'printer', 'camera', 'iot'];
  out(info(`Bruteforce ${WL.length} noms…`));
  let okCount = 0;
  await Promise.all(WL.map(async (w) => {
    const fqdn = `${w}.${TARGET}`;
    if (subs.has(fqdn)) return;
    try { await dns.resolve4(fqdn); subs.add(fqdn); okCount++; out(`  ${ok(fqdn)}`); } catch {}
  }));
  const list = [...subs].sort();
  out(`\n${C.bold}Total : ${list.length} sous-domaines${C.reset}`);
  list.slice(0, 100).forEach(s => out('  - ' + s));
  if (list.length > 100) out(C.dim + `  … +${list.length - 100} autres (voir rapport)` + C.reset);
  return list;
}

// ============ 8. PORTS ============
function scanPort(ip, port, timeout = 1500) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    s.setTimeout(timeout);
    s.on('connect', () => { s.destroy(); resolve(true); });
    s.on('timeout', () => { s.destroy(); resolve(false); });
    s.on('error', () => resolve(false));
    s.connect(port, ip);
  });
}
const COMMON_PORTS = [[21, 'FTP'], [22, 'SSH'], [23, 'Telnet'], [25, 'SMTP'], [53, 'DNS'], [80, 'HTTP'], [110, 'POP3'], [143, 'IMAP'], [443, 'HTTPS'], [445, 'SMB'], [3306, 'MySQL'], [3389, 'RDP'], [5900, 'VNC'], [8080, 'HTTP-alt'], [8443, 'HTTPS-alt'], [8000, 'HTTP-dev'], [8888, 'HTTP-dev'], [3000, 'Node'], [5000, 'Flask'], [8008, 'HTTP-alt'], [9000, 'PHP-FPM/dev'], [27017, 'MongoDB'], [6379, 'Redis'], [5432, 'PostgreSQL'], [11211, 'Memcached'], [21 + 0, '—'], [587, 'SMTP-sub'], [993, 'IMAPS'], [995, 'POP3S'], [2082, 'cPanel'], [2083, 'cPanel-SSL'], [2087, 'WHM'], [33060, 'MySQL-X']];
async function modPorts() {
  section(`SCAN PORTS — ${TARGET}`);
  let ip;
  try { ip = (await dns.resolve4(TARGET))[0]; } catch { out(ko('IP introuvable')); return []; }
  out(info(`Scan ${COMMON_PORTS.length} ports sur ${ip}…`));
  const open = [];
  for (const [p, svc] of COMMON_PORTS) {
    process.stdout.write(`\r  test ${String(p).padEnd(6)} ${svc}…`);
    if (await scanPort(ip, p)) { open.push([p, svc]); console.log(`\r  ${ok(`port ${p} OUVERT (${svc})`)}`); }
  }
  console.log('');
  if (!open.length) out(warn('Aucun port commun ouvert (ou filtré/firewall)'));
  else out(`${C.red}${C.bold}⚠ Ports ouverts : ${open.map(([p, s]) => `${p}/${s}`).join(', ')}${C.reset}`);
  return open;
}

// ============ 9. FICHIERS SENSIBLES ============
async function modSensitive() {
  section(`FICHIERS SENSIBLES / ADMIN — ${TARGET}`);
  const paths = ['/.git/HEAD', '/.env', '/.htaccess', '/wp-config.php.bak', '/wp-admin/', '/wp-login.php', '/administrator/', '/phpinfo.php', '/info.php', '/server-status/', '/server-info/', '/.DS_Store', '/backup.zip', '/backup.tar.gz', '/db.sql', '/dump.sql', '/config.php', '/config.bak', '/.svn/entries', '/.hg/requires', '/Dockerfile', '/docker-compose.yml', '/package.json', '/composer.json', '/.well-known/change-password', '/api/', '/api/docs', '/swagger.json', '/swagger-ui/', '/graphql', '/.git/config', '/admin/', '/login', '/phpmyadmin/', '/pma/', '/aws.yml', '/credentials.xml'];
  const hits = [];
  for (const p of paths) {
    const r = await fetchSmart(p, { timeout: 7000 });
    const code = r ? r.status : 'ERR';
    const good = r && r.status === 200 && r.body.length > 10;
    // faux positifs : page 200 identique à la home (soft-404)
    if (good) { hits.push(p); out(`  ${C.red}${C.bold}[${code}] ${p} ← À VÉRIFIER !${C.reset}`); }
    else out(`  ${C.dim}[${code}] ${p}${C.reset}`);
  }
  if (hits.length) out(`\n${C.red}★ ${hits.length} chemin(s) intéressant(s) : ${hits.join(', ')}${C.reset}`);
  else out(`\n${ok('Rien d’évident')}`);
  return hits;
}

// ============ 10. SSL ============
function getCert(host) {
  return new Promise((resolve) => {
    const s = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 8000 }, () => {
      const c = s.getPeerCertificate(true);
      s.end(); resolve(c);
    });
    s.on('error', () => resolve(null));
    s.on('timeout', () => { try { s.destroy(); } catch {} resolve(null); });
  });
}
async function modSSL() {
  section(`CERTIFICAT SSL — ${TARGET}`);
  const c = await getCert(TARGET);
  if (!c || !c.subject) { out(ko('Pas de TLS sur 443 ou certificat illisible')); return; }
  out(`${info('Sujet  :')} ${c.subject.CN || JSON.stringify(c.subject)}`);
  out(`${info('Émetteur :')} ${c.issuer.CN || JSON.stringify(c.issuer)} (${c.issuer.O || ''})`);
  out(`${info('Valide :')} ${c.valid_from} → ${c.valid_to}`);
  const days = Math.round((new Date(c.valid_to) - Date.now()) / 86400000);
  out(days < 0 ? ko(`EXPIRÉ depuis ${-days} j`) : days < 30 ? warn(`Expire dans ${days} j`) : ok(`Expire dans ${days} j`));
  const sans = c.subjectaltname ? c.subjectaltname.replace(/DNS:/g, '').split(',').map(s => s.trim()) : [];
  if (sans.length) { out(`${info('SANs (autres domaines sur ce cert — pistes !) :')}`); sans.slice(0, 30).forEach(s => out('  - ' + s)); }
}

// ============ FULL + EXPORT ============
async function modFull() {
  out(`\n${C.bgBlue}${C.bold}  AUDIT COMPLET — ${TARGET}  ${C.reset}\n`);
  await modIP(); await modDNS(); await modWhois(); await modHeaders();
  await modFiles(); await modCrawl(); await modSubdomains(); await modPorts();
  await modSensitive(); await modSSL();
  out(`\n${C.bgGreen}${C.bold}  AUDIT TERMINÉ — pense à exporter [13]  ${C.reset}\n`);
}
function modExport() {
  if (!TARGET) { out(ko('Pas de cible')); return; }
  const f = `HAweb-infoCK-${TARGET.replace(/[^a-z0-9.-]/g, '')}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.md`;
  fs.writeFileSync(f, `# Rapport HAweb-infoCK — ${TARGET}\n_Date : ${new Date().toLocaleString('fr-FR')}_\n\n\`\`\`\n${LOG.join('\n')}\n\`\`\`\n`);
  out(ok(`Rapport sauvé : ${f}`));
}

// ============ UI TERMINAL À BOUTONS ============
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
function ask(q) { return new Promise(res => rl.question(q, res)); }
function clear() { console.clear(); }
function banner() {
  console.log(`\n  ${C.cyan}${C.bold}🔍 HAweb-infoCK${C.reset}`);
  console.log(`  ${C.dim}Recon web CTF : hébergeur • DNS • whois • pages • sous-domaines • ports • SSL${C.reset}`);
}
function btn(n, label) { return `  ${C.bgBlue}${C.bold} ${n} ${C.reset} ${label}`; }
function drawMenu() {
  clear(); banner();
  console.log('');
  if (TARGET) console.log(`  ${C.bold}CIBLE :${C.reset} ${C.bgGreen}${C.bold} ${TARGET} ${C.reset}   ${C.dim}(touche ${C.reset}${C.bold}T${C.reset}${C.dim} pour changer)${C.reset}`);
  else console.log(`  ${C.bold}CIBLE :${C.reset} ${C.bgRed}${C.bold}  non définie — tape 1  ${C.reset}`);
  console.log(`  ${C.dim}${'─'.repeat(62)}${C.reset}`);
  console.log(btn('1', '🎯  Définir / changer la cible  [ espace pour marquer le nom du site ]'));
  console.log(btn('2', '🌐  IP + Hébergeur + Géolocalisation'));
  console.log(btn('3', '📡  DNS complet (A, MX, NS, TXT, SPF, DMARC)'));
  console.log(btn('4', '📄  WHOIS du domaine'));
  console.log(btn('5', '🧱  Headers HTTP + technos détectées'));
  console.log(btn('6', '🤖  robots.txt / sitemap.xml / security.txt'));
  console.log(btn('7', '🕷️   Crawler — toutes les pages du site'));
  console.log(btn('8', '🔍  Sous-domaines (crt.sh + bruteforce)'));
  console.log(btn('9', '🚪  Scan des ports communs'));
  console.log(btn('10', '📁  Fichiers sensibles & pages admin'));
  console.log(btn('11', '🔒  Certificat SSL + domaines liés'));
  console.log(btn('12', '💥  TOUT LANCER — audit complet'));
  console.log(btn('13', '💾  Exporter le rapport (.md)'));
  console.log(btn('0', '❌  Quitter'));
  console.log(`  ${C.dim}${'─'.repeat(62)}${C.reset}`);
}
async function needTarget() {
  if (TARGET) return true;
  const t = await ask(`\n${C.bold}🌐 Entre le nom du site (ex: example.com) :${C.reset} `);
  TARGET = cleanTarget(t);
  if (!TARGET) { console.log(ko('Cible vide !')); await ask('Entrée pour continuer…'); return false; }
  return true;
}
async function loop() {
  if (process.argv.includes('--full') && TARGET) { await modFull(); modExport(); rl.close(); return; }
  while (true) {
    drawMenu();
    const ch = (await ask(`\n${C.bold}👉 Choisis un bouton [0-13 / T] :${C.reset} `)).trim().toLowerCase();
    if (ch === '0' || ch === 'q' || ch === 'quit' || ch === 'exit') { console.log('\n👋 Bon CTF !'); break; }
    if (ch === '1' || ch === 't' || ch === 'cible') {
      const t = await ask(`\n${C.bold}🌐 Nom du site :${C.reset} `);
      const c = cleanTarget(t);
      if (c) { TARGET = c; LOG = []; console.log(ok(`Cible = ${TARGET}`)); }
      else console.log(ko('Vide, cible inchangée'));
      await ask('Entrée pour continuer…'); continue;
    }
    const need = ['2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13'];
    if (!need.includes(ch)) { console.log(ko('Choix invalide')); await ask('Entrée…'); continue; }
    if (ch !== '13' && !(await needTarget())) continue;
    try {
      if (ch === '2') await modIP();
      if (ch === '3') await modDNS();
      if (ch === '4') await modWhois();
      if (ch === '5') await modHeaders();
      if (ch === '6') await modFiles();
      if (ch === '7') await modCrawl();
      if (ch === '8') await modSubdomains();
      if (ch === '9') await modPorts();
      if (ch === '10') await modSensitive();
      if (ch === '11') await modSSL();
      if (ch === '12') await modFull();
      if (ch === '13') modExport();
    } catch (e) { out(ko('Erreur : ' + e.message)); }
    await ask(`\n${C.dim}Entrée pour revenir au menu…${C.reset}`);
  }
  rl.close();
}
loop();
