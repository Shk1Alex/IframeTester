import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const PORT = Number(process.env.PORT) || 8787;
const DIR = path.dirname(fileURLToPath(import.meta.url));
const MAX_REDIRECTS = 10;
const TIMEOUT_MS = 15000;
const DEFAULT_PORT = { 'http:': '80', 'https:': '443' };


const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Sec-Fetch-Dest': 'iframe',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'cross-site',
  'Upgrade-Insecure-Requests': '1',
};

// ---------- запрос с ручным проходом по редиректам ----------
async function fetchChain(startUrl) {
  const chain = [];
  let url = startUrl;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const res = await fetch(url, {
      redirect: 'manual',
      headers: BROWSER_HEADERS,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    res.body?.cancel().catch(() => {}); // тело не нужно
    chain.push({ url, status: res.status, headers: res.headers });
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) {
      url = new URL(loc, url).href;
      continue;
    }
    return chain;
  }
  throw new Error(`Больше ${MAX_REDIRECTS} редиректов`);
}

// ---------- CSP ----------
function parseCsp(raw) {
  if (!raw) return [];
  // Несколько заголовков CSP склеиваются через запятую - каждая часть отдельная политика
  return raw.split(',').map(policy => {
    const dirs = {};
    for (const part of policy.split(';')) {
      const [name, ...vals] = part.trim().split(/\s+/);
      if (name && !(name.toLowerCase() in dirs)) dirs[name.toLowerCase()] = vals;
    }
    return dirs;
  });
}

function matchSource(src, anc, target) {
  const s = src.toLowerCase();
  if (s === "'none'") return false;
  if (s === "'self'") return anc.origin === target.origin;
  if (s === '*') return anc.protocol === 'http:' || anc.protocol === 'https:';
  const schemeOk = sch => sch === anc.protocol || (sch === 'http:' && anc.protocol === 'https:');
  if (/^[a-z][a-z0-9+.-]*:$/.test(s)) return schemeOk(s);

  const m = s.match(/^(?:([a-z][a-z0-9+.-]*):\/\/)?(\*\.)?([a-z0-9.-]+|\*)(?::(\d+|\*))?(?:\/.*)?$/);
  if (!m) return false;
  const [, scheme, wild, host, port] = m;
  if (!schemeOk(scheme ? scheme + ':' : target.protocol)) return false;
  if (host !== '*') {
    if (wild ? !anc.hostname.endsWith('.' + host) : anc.hostname !== host) return false;
  }
  const ancPort = anc.port || DEFAULT_PORT[anc.protocol];
  if (port === '*') return true;
  if (port) return port === ancPort;
  return ancPort === DEFAULT_PORT[anc.protocol];
}


function analyze(chain, ancestorOrigin) {
  const final = chain.at(-1);
  const h = final.headers;
  const target = new URL(final.url);
  let anc = null;
  try { anc = new URL(ancestorOrigin); } catch {}

  const findings = [];
  const add = (level, header, value, message) => findings.push({ level, header, value, message });
  let blocked = false;

  if (final.status >= 400)
    add('warn', 'Status', String(final.status),
      `Страница ответила ${final.status}. Заголовки страницы ошибки могут отличаться от живой checkout-сессии - проверяйте на рабочей ссылке.`);
  if ((h.get('cf-mitigated') || '').toLowerCase() === 'challenge')
    add('warn', 'cf-mitigated', 'challenge',
      'Cloudflare отдал серверному запросу проверку на бота: заголовки ниже от страницы челленджа, а не от платёжки.');


  const fa = parseCsp(h.get('content-security-policy'))
    .filter(p => p['frame-ancestors'])
    .map(p => p['frame-ancestors']);
  const xfo = h.get('x-frame-options');

  if (fa.length) {
    for (const sources of fa) {
      const value = 'frame-ancestors ' + sources.join(' ');
      const ok = anc && sources.some(s => matchSource(s, anc, target));
      if (ok) {
        add('ok', 'Content-Security-Policy', value, `${ancestorOrigin} разрешён директивой frame-ancestors.`);
      } else {
        blocked = true;
        add('block', 'Content-Security-Policy', value,
          `${ancestorOrigin} не входит в frame-ancestors - браузер не покажет страницу во фрейме.`);
      }
    }
    if (xfo) add('info', 'X-Frame-Options', xfo,
      'Игнорируется: при наличии CSP frame-ancestors браузер смотрит только на CSP.');
  } else if (xfo) {
    // 2. X-Frame-Options
    const vals = xfo.split(',').map(v => v.trim().toLowerCase());
    if (vals.includes('deny')) {
      blocked = true;
      add('block', 'X-Frame-Options', xfo, 'DENY - встраивание во фрейм запрещено для всех сайтов.');
    } else if (vals.includes('sameorigin')) {
      if (anc && anc.origin === target.origin) {
        add('ok', 'X-Frame-Options', xfo, 'SAMEORIGIN, origin родителя совпадает.');
      } else {
        blocked = true;
        add('block', 'X-Frame-Options', xfo, `SAMEORIGIN - во фрейме можно открыть только с ${target.origin}.`);
      }
    } else {
      add('info', 'X-Frame-Options', xfo,
        'Значение не поддерживается современными браузерами (включая ALLOW-FROM) и игнорируется.');
    }
  } else {
    add('ok', 'X-Frame-Options / CSP', '—',
      'Нет ни X-Frame-Options, ни CSP frame-ancestors - заголовки встраивание не запрещают.');
  }


  for (const p of parseCsp(h.get('content-security-policy-report-only')).filter(p => p['frame-ancestors']))
    add('info', 'Content-Security-Policy-Report-Only', 'frame-ancestors ' + p['frame-ancestors'].join(' '),
      'Report-Only не блокирует, только отправляет отчёты. Возможно, скоро включат в боевом режиме.');


  const pp = h.get('permissions-policy');
  if (pp && /(^|,)\s*payment\s*=\s*\(\s*\)/i.test(pp))
    add('warn', 'Permissions-Policy', 'payment=()',
      'Payment Request API на странице отключён: Apple Pay / Google Pay через него во фрейме не заработают.');


  const seen = new Set();
  for (const hop of chain) {
    for (const c of hop.headers.getSetCookie()) {
      const name = c.split('=')[0].trim();
      if (seen.has(name)) continue;
      seen.add(name);
      const a = c.toLowerCase();
      if (!/;\s*samesite\s*=\s*none/.test(a))
        add('warn', 'Set-Cookie', name,
          'Без SameSite=None cookie не сохранится и не отправится во фрейме на чужом сайте - сессия платёжки может теряться.');
      else if (!/;\s*secure/.test(a))
        add('warn', 'Set-Cookie', name, 'SameSite=None без Secure - браузер отклонит cookie.');
      else if (!/;\s*partitioned/.test(a))
        add('info', 'Set-Cookie', name,
          'SameSite=None; Secure-ок, но при блокировке сторонних cookie (Safari, инкогнито) не сработает. Надёжнее Partitioned.');
    }
  }

  if (target.protocol === 'http:')
    add('warn', 'URL', target.href, 'HTTP-страница во фрейме на HTTPS-сайте мерчанта будет заблокирована как mixed content.');

  const verdict = blocked ? 'blocked' : findings.some(f => f.level === 'warn') ? 'warn' : 'allowed';
  return { verdict, findings };
}

function serializeHeaders(headers) {
  const out = {};
  for (const [k, v] of headers) if (k !== 'set-cookie') out[k] = v;
  const cookies = headers.getSetCookie();
  if (cookies.length) out['set-cookie'] = cookies.map(c => c.split(';')[0].split('=')[0] + '=… ' + c.slice(c.indexOf(';')));
  return out;
}

// ---------- HTTP ----------
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host}`);

  if (u.pathname === '/') {
    try {
      const html = await readFile(path.join(DIR, 'iframe-tester.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    } catch {
      res.writeHead(500); return res.end('iframe-tester.html не найден рядом с server.mjs');
    }
  }

  if (u.pathname === '/check') {
    const send = (code, obj) => {
      res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify(obj));
    };
    let target;
    try {
      target = new URL(u.searchParams.get('url'));
      if (!/^https?:$/.test(target.protocol)) throw 0;
    } catch {
      return send(400, { error: 'Некорректный URL - нужен http(s)://…' });
    }
    const ancestor = u.searchParams.get('ancestor') || `http://${req.headers.host}`;
    try {
      const chain = await fetchChain(target.href);
      const final = chain.at(-1);
      return send(200, {
        ancestor,
        chain: chain.map(c => ({ url: c.url, status: c.status })),
        finalUrl: final.url,
        status: final.status,
        headers: serializeHeaders(final.headers),
        ...analyze(chain, ancestor),
      });
    } catch (e) {
      const reason = e.name === 'TimeoutError' ? `таймаут ${TIMEOUT_MS / 1000} с` : (e.cause?.code || e.cause?.message || e.message);
      return send(502, { error: `Запрос не прошёл: ${reason}` });
    }
  }

  res.writeHead(404); res.end();
});

server.listen(PORT, '127.0.0.1', () => console.log(`iframe-тестер: http://localhost:${PORT}`));
