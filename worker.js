/**
 * SEO Checker — Cloudflare Worker
 * النشر: wrangler deploy  أو  Dashboard > Workers > Paste
 *
 * ── المتغيرات المطلوبة في wrangler.toml أو Dashboard > Settings > Variables ──
 *   ALLOWED_ORIGIN  = "https://yourdomain.com"   (دومينك الفعلي)
 *   RATE_LIMIT_KV   = binding لـ KV namespace اسمه SEO_RL
 */

// ═══════════════════════════════════════════════
//  CONFIG
// ═══════════════════════════════════════════════
const CONFIG = {
  // عدد الطلبات المسموح بها لكل IP في الفترة الزمنية
  RATE_LIMIT_REQUESTS : 10,
  // الفترة الزمنية بالثواني (10 دقائق)
  RATE_LIMIT_WINDOW_S : 600,
  // حجم HTML الأقصى للفحص (2 MB)
  MAX_HTML_BYTES      : 2 * 1024 * 1024,
  // مهلة الاتصال بالموقع المستهدف
  FETCH_TIMEOUT_MS    : 10_000,
  // مدة Cache للنتائج بالثواني (30 دقيقة)
  CACHE_TTL_S         : 1800,
  // الحد الأقصى للروابط المكسورة للفحص (لتجنب الإبطاء)
  MAX_LINKS_TO_CHECK  : 20,
  // الحد الأقصى لصفحات الـ Crawl
  MAX_CRAWL_PAGES     : 5,
};

// ── البروتوكولات المسموحة فقط ──
const ALLOWED_PROTOCOLS = new Set(['https:', 'http:']);

// ── النطاقات المحظورة (شبكة داخلية) ──
const BLOCKED_HOSTS = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|::1)/i;

// ═══════════════════════════════════════════════
//  CORS BUILDER  — يُبنى ديناميكياً من env
// ═══════════════════════════════════════════════
function buildCors(env, requestOrigin) {
  // في حالة لم يُضبط ALLOWED_ORIGIN نقبل أي origin (مرحلة التطوير فقط)
  const allowed = env?.ALLOWED_ORIGIN ?? '*';

  // إذا كان مضبوطاً، نتحقق من المطابقة
  const originOk = allowed === '*' || requestOrigin === allowed;
  const origin   = originOk ? (requestOrigin ?? '*') : 'null';

  return {
    'Access-Control-Allow-Origin' : origin,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age'      : '86400',
    'Vary'                        : 'Origin',
  };
}

// ═══════════════════════════════════════════════
//  RATE LIMITER  — يعتمد على KV
// ═══════════════════════════════════════════════
async function checkRateLimit(kv, ip) {
  // إذا لم يكن KV مربوطاً نتجاوز الفحص (مرحلة التطوير)
  if (!kv) return { allowed: true, remaining: 999, resetIn: 0 };

  const key     = `rl:${ip}`;
  const now     = Math.floor(Date.now() / 1000);
  const raw     = await kv.get(key);
  const record  = raw ? JSON.parse(raw) : { count: 0, window_start: now };

  // إعادة تعيين العداد إذا انتهت الفترة
  if (now - record.window_start >= CONFIG.RATE_LIMIT_WINDOW_S) {
    record.count        = 0;
    record.window_start = now;
  }

  record.count++;
  const remaining = Math.max(0, CONFIG.RATE_LIMIT_REQUESTS - record.count);
  const resetIn   = CONFIG.RATE_LIMIT_WINDOW_S - (now - record.window_start);

  // نحفظ مع TTL = نهاية الفترة الحالية
  await kv.put(key, JSON.stringify(record), { expirationTtl: CONFIG.RATE_LIMIT_WINDOW_S });

  return {
    allowed  : record.count <= CONFIG.RATE_LIMIT_REQUESTS,
    remaining,
    resetIn,
    total    : record.count,
  };
}

// ═══════════════════════════════════════════════
//  MAIN HANDLER
// ═══════════════════════════════════════════════
export default {
  async fetch(request, env) {
    const requestOrigin = request.headers.get('Origin') ?? '';
    const cors          = buildCors(env, requestOrigin);

    // ── CORS Preflight ──
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    // ── Method guard ──
    if (request.method !== 'GET') {
      return json({ error: 'Method not allowed' }, 405, cors);
    }

    const url = new URL(request.url);

    // ── Route: /check ──
    if (url.pathname === '/check') {

      // 1. CORS: رفض الطلبات من origins غير مسموح بها
      if (env?.ALLOWED_ORIGIN && env.ALLOWED_ORIGIN !== '*') {
        if (requestOrigin !== env.ALLOWED_ORIGIN) {
          return json({ error: 'Origin غير مسموح به' }, 403, cors);
        }
      }

      // 2. Rate Limiting
      const ip    = request.headers.get('CF-Connecting-IP') ?? 'unknown';
      const limit = await checkRateLimit(env?.RATE_LIMIT_KV, ip);

      if (!limit.allowed) {
        return json(
          { error: `تجاوزت الحد المسموح (${CONFIG.RATE_LIMIT_REQUESTS} طلبات / ${CONFIG.RATE_LIMIT_WINDOW_S / 60} دقيقة). حاول بعد ${limit.resetIn} ثانية.` },
          429,
          {
            ...cors,
            'Retry-After'               : String(limit.resetIn),
            'X-RateLimit-Limit'         : String(CONFIG.RATE_LIMIT_REQUESTS),
            'X-RateLimit-Remaining'     : '0',
            'X-RateLimit-Reset'         : String(Math.floor(Date.now() / 1000) + limit.resetIn),
          }
        );
      }

      // 3. Validate URL param
      const target = url.searchParams.get('url');
      if (!target) {
        return json({ error: 'يجب إرسال url كـ query parameter' }, 400, cors);
      }

      let targetUrl;
      try {
        targetUrl = new URL(target.startsWith('http') ? target : 'https://' + target);
      } catch {
        return json({ error: 'رابط غير صالح' }, 400, cors);
      }

      // 4. Block internal/private networks
      if (!ALLOWED_PROTOCOLS.has(targetUrl.protocol)) {
        return json({ error: 'بروتوكول غير مسموح به — يُقبل http و https فقط' }, 400, cors);
      }
      if (BLOCKED_HOSTS.test(targetUrl.hostname)) {
        return json({ error: 'لا يمكن فحص عناوين الشبكة الداخلية' }, 400, cors);
      }

      // 5. Check Cache
      const noCache   = url.searchParams.get('nocache') === '1';
      const normalizedHref = targetUrl.origin + targetUrl.pathname.replace(/\/$/, '') + targetUrl.search;
      const cacheKey  = `cache:${normalizedHref}`;
      if (!noCache && env?.RATE_LIMIT_KV) {
        const cached = await env.RATE_LIMIT_KV.get(cacheKey);
        if (cached) {
          return json(
            { ...JSON.parse(cached), fromCache: true },
            200,
            { ...cors, 'X-Cache': 'HIT', 'X-RateLimit-Limit': String(CONFIG.RATE_LIMIT_REQUESTS), 'X-RateLimit-Remaining': String(limit.remaining) }
          );
        }
      }

      // 6. Run analysis
      try {
        const result = await analyzeSite(targetUrl, env);

        // Save to cache
        if (env?.RATE_LIMIT_KV) {
          await env.RATE_LIMIT_KV.put(cacheKey, JSON.stringify(result), { expirationTtl: CONFIG.CACHE_TTL_S });
        }

        return json(
          { ...result, fromCache: false },
          200,
          {
            ...cors,
            'X-Cache'              : 'MISS',
            'X-RateLimit-Limit'    : String(CONFIG.RATE_LIMIT_REQUESTS),
            'X-RateLimit-Remaining': String(limit.remaining),
          }
        );
      } catch (err) {
        const status  = err.httpStatus ?? 502;
        const code    = err.code       ?? 'UNKNOWN';
        return json(
          { error: err.message, code, tip: getTip(code) },
          status,
          cors
        );
      }
    }

    // ── Route: /crawl ── (multi-page crawl)
    if (url.pathname === '/crawl') {

      if (env?.ALLOWED_ORIGIN && env.ALLOWED_ORIGIN !== '*') {
        if (requestOrigin !== env.ALLOWED_ORIGIN) {
          return json({ error: 'Origin غير مسموح به' }, 403, cors);
        }
      }

      const ip    = request.headers.get('CF-Connecting-IP') ?? 'unknown';
      const limit = await checkRateLimit(env?.RATE_LIMIT_KV, ip);
      if (!limit.allowed) {
        return json({ error: 'Rate limit exceeded' }, 429, cors);
      }

      const target = url.searchParams.get('url');
      if (!target) return json({ error: 'يجب إرسال url' }, 400, cors);

      let targetUrl;
      try {
        targetUrl = new URL(target.startsWith('http') ? target : 'https://' + target);
      } catch {
        return json({ error: 'رابط غير صالح' }, 400, cors);
      }

      if (BLOCKED_HOSTS.test(targetUrl.hostname)) {
        return json({ error: 'لا يمكن فحص عناوين الشبكة الداخلية' }, 400, cors);
      }

      try {
        const crawlResult = await crawlSite(targetUrl, env);
        return json(crawlResult, 200, cors);
      } catch (err) {
        return json({ error: err.message }, 500, cors);
      }
    }

    // ── Route: / — health check ──
    return json({ status: 'ok', version: '2.0.0', message: 'SEO Checker API' }, 200, cors);
  }
};

// نصيحة سريعة مرتبطة بكل كود خطأ
function getTip(code) {
  const tips = {
    TIMEOUT      : 'جرّب مرة أخرى، أو تأكد أن الموقع يعمل من متصفحك أولاً.',
    DNS_FAIL     : 'تأكد من كتابة الدومين بشكل صحيح — مثال: example.com',
    SSL_ERROR    : 'شهادة SSL منتهية أو مشكلة في الإعداد. تحقق من Cloudflare أو مزود الاستضافة.',
    CONNECTION   : 'الموقع قد يحجب طلبات الـ bots. جرّب إضافة User-Agent مختلف أو تحقق من Firewall.',
    NOT_HTML     : 'تأكد أن الرابط يشير إلى صفحة ويب وليس API أو ملف تحميل.',
    TOO_LARGE    : 'الصفحة كبيرة جداً. جرّب فحص صفحة داخلية أصغر.',
    HTTP_ERROR   : 'تحقق من أن الموقع يعمل وأنه لا يحتاج تسجيل دخول.',
    REDIRECT_LOOP: 'هناك حلقة redirect في إعدادات الموقع — راجع .htaccess أو Cloudflare Rules.',
    UNKNOWN      : 'خطأ غير متوقع. أعد المحاولة أو أرسل لنا التفاصيل.',
  };
  return tips[code] ?? tips.UNKNOWN;
}

// ═══════════════════════════════════════════════
//  ERROR CODES  — رموز الأخطاء الموحدة
// ═══════════════════════════════════════════════
const ERR = {
  TIMEOUT        : { code: 'TIMEOUT',         http: 504, ar: 'انتهت مهلة الاتصال بالموقع (10 ثواني) — قد يكون بطيئاً أو محجوباً' },
  DNS_FAIL       : { code: 'DNS_FAIL',        http: 502, ar: 'فشل تحليل اسم النطاق — تأكد أن الدومين صحيح وقيد الخدمة' },
  SSL_ERROR      : { code: 'SSL_ERROR',       http: 502, ar: 'خطأ في شهادة SSL — الشهادة منتهية أو غير صالحة' },
  CONNECTION     : { code: 'CONNECTION',      http: 502, ar: 'تعذّر الاتصال بالموقع — قد يكون معطّلاً أو يحجب الـ bots' },
  NOT_HTML       : { code: 'NOT_HTML',        http: 422, ar: 'الرابط لا يعيد صفحة HTML — تأكد أنه رابط موقع وليس API أو ملف' },
  TOO_LARGE      : { code: 'TOO_LARGE',       http: 413, ar: 'حجم الصفحة أكبر من 2MB — لا يمكن تحليلها' },
  HTTP_ERROR     : { code: 'HTTP_ERROR',      http: 502, ar: null }, // dynamic
  REDIRECT_LOOP  : { code: 'REDIRECT_LOOP',   http: 502, ar: 'اكتُشفت حلقة إعادة توجيه لا نهائية' },
  UNKNOWN        : { code: 'UNKNOWN',         http: 500, ar: 'خطأ غير متوقع' },
};

function seoError(type, extra = '') {
  const e = new Error(type.ar + (extra ? ` (${extra})` : ''));
  e.code    = type.code;
  e.httpStatus = type.http;
  return e;
}

// ═══════════════════════════════════════════════
//  MAIN ANALYZER
// ═══════════════════════════════════════════════
async function analyzeSite(targetUrl, env) {
  const startTime = Date.now();

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort('timeout'), CONFIG.FETCH_TIMEOUT_MS);

  let response, html, finalUrl, redirected;
  try {
    response = await fetch(targetUrl.href, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SEOCheckerBot/1.0)',
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
        'Accept-Language': 'ar,en;q=0.9',
      },
      redirect: 'follow',
    });
  } catch (err) {
    clearTimeout(timeout);
    const msg = err.message?.toLowerCase() ?? '';

    if (err.name === 'AbortError' || msg.includes('timeout'))
      throw seoError(ERR.TIMEOUT);
    if (msg.includes('ssl') || msg.includes('certificate') || msg.includes('tls'))
      throw seoError(ERR.SSL_ERROR);
    if (msg.includes('dns') || msg.includes('resolve') || msg.includes('getaddrinfo'))
      throw seoError(ERR.DNS_FAIL);
    if (msg.includes('redirect'))
      throw seoError(ERR.REDIRECT_LOOP);
    throw seoError(ERR.CONNECTION, err.message);
  }
  clearTimeout(timeout);

  // ── HTTP status check ──
  if (response.status === 401 || response.status === 403) {
    throw seoError(ERR.HTTP_ERROR,
      `HTTP ${response.status} — الموقع يحجب الـ bots أو يحتاج صلاحية`);
  }
  if (response.status === 404) {
    throw seoError(ERR.HTTP_ERROR, 'HTTP 404 — الصفحة غير موجودة');
  }
  if (response.status >= 500) {
    throw seoError(ERR.HTTP_ERROR, `HTTP ${response.status} — خطأ في سيرفر الموقع المستهدف`);
  }
  if (response.status >= 400) {
    throw seoError(ERR.HTTP_ERROR, `HTTP ${response.status}`);
  }

  // ── Content-Type check ──
  const ct = response.headers.get('content-type') ?? '';
  if (!ct.includes('html') && !ct.includes('xml') && ct !== '') {
    throw seoError(ERR.NOT_HTML, ct);
  }

  // ── Size check (streaming) ──
  const reader        = response.body.getReader();
  const chunks        = [];
  let   totalBytes    = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > CONFIG.MAX_HTML_BYTES) {
      reader.cancel();
      throw seoError(ERR.TOO_LARGE);
    }
    chunks.push(value);
  }

  // Combine chunks → string
  const combined = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) { combined.set(chunk, offset); offset += chunk.byteLength; }
  html       = new TextDecoder('utf-8', { fatal: false }).decode(combined);
  finalUrl   = response.url;
  redirected = finalUrl !== targetUrl.href;

  const fetchTime = Date.now() - startTime;

  // ── Parse HTML manually (no DOM in Workers) ──
  const checks = {
    // 1. Title
    ...checkTitle(html),
    // 2. Meta Description
    ...checkMetaDescription(html),
    // 3. Headings
    ...checkHeadings(html),
    // 4. Images Alt
    ...checkImages(html),
    // 5. HTTPS
    ...checkHttps(targetUrl, finalUrl, response),
    // 6. Canonical
    ...checkCanonical(html, finalUrl),
    // 7. Robots meta
    ...checkRobotsMeta(html),
    // 8. Open Graph
    ...checkOpenGraph(html),
    // 9. Structured Data
    ...checkStructuredData(html),
    // 10. Lang attribute
    ...checkLang(html),
    // 11. Viewport
    ...checkViewport(html),
    // 12. Word count
    ...checkWordCount(html),
    // 13. Twitter Cards ✨ NEW
    ...checkTwitterCards(html),
    // 14. Links (internal/external) ✨ NEW
    ...checkLinks(html, finalUrl),
  };

  // Fetch robots.txt, sitemap, PageSpeed & broken links in parallel
  const [robotsResult, sitemapResult, pagespeedResult, brokenLinksResult] = await Promise.allSettled([
    checkRobotsTxt(targetUrl),
    checkSitemap(targetUrl, html),
    checkPageSpeed(targetUrl, env?.PAGESPEED_KEY),
    checkBrokenLinks(html, finalUrl),
  ]);

  Object.assign(checks,
    robotsResult.status === 'fulfilled' ? robotsResult.value : { robotsTxt: { status: 'error', message: 'تعذّر الوصول' } },
    sitemapResult.status === 'fulfilled' ? sitemapResult.value : { sitemap: { status: 'error', message: 'تعذّر الوصول' } },
    brokenLinksResult.status === 'fulfilled' ? brokenLinksResult.value : { brokenLinks: { status: 'warning', broken: [], checked: 0, message: 'تعذّر فحص الروابط' } },
  );

  const pagespeed = pagespeedResult.status === 'fulfilled' ? pagespeedResult.value : null;

  // ── Score ──
  const { score, breakdown, categories, summary } = calcScore(checks);

  // ── Issues list ──
  const issues = buildIssues(checks);

  return {
    url: targetUrl.href,
    finalUrl,
    redirected,
    statusCode: response.status,
    fetchTimeMs: fetchTime,
    score,
    breakdown,
    categories,
    summary,
    checks,
    issues,
    pagespeed,
    checkedAt: new Date().toISOString(),
  };
}

// ═══════════════════════════════════════════════
//  INDIVIDUAL CHECKS
// ═══════════════════════════════════════════════

function checkTitle(html) {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!match) return { title: { status: 'error', value: null, message: 'Title مفقود' } };
  const title = decode(match[1].trim());
  const len = title.length;
  if (len === 0) return { title: { status: 'error', value: '', message: 'Title فارغ' } };
  if (len < 30) return { title: { status: 'warning', value: title, length: len, message: `Title قصير (${len} حرف) — المثالي 50-60` } };
  if (len > 70) return { title: { status: 'warning', value: title, length: len, message: `Title طويل (${len} حرف) — سيُقطع في نتائج البحث` } };
  return { title: { status: 'good', value: title, length: len, message: 'Title ممتاز' } };
}

function checkMetaDescription(html) {
  const match = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i)
               || html.match(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i);
  if (!match) return { metaDescription: { status: 'error', value: null, message: 'Meta Description مفقود' } };
  const desc = decode(match[1].trim());
  const len = desc.length;
  if (len === 0) return { metaDescription: { status: 'error', value: '', message: 'Meta Description فارغ' } };
  if (len < 70) return { metaDescription: { status: 'warning', value: desc, length: len, message: `قصير (${len} حرف) — المثالي 120-160` } };
  if (len > 170) return { metaDescription: { status: 'warning', value: desc, length: len, message: `طويل (${len} حرف) — سيُقطع في نتائج البحث` } };
  return { metaDescription: { status: 'good', value: desc, length: len, message: 'Meta Description ممتاز' } };
}

function checkHeadings(html) {
  const h1matches = [...html.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/gi)];
  const h2matches = [...html.matchAll(/<h2[^>]*>([\s\S]*?)<\/h2>/gi)];
  const h3matches = [...html.matchAll(/<h3[^>]*>([\s\S]*?)<\/h3>/gi)];

  const h1texts = h1matches.map(m => decode(stripTags(m[1])).trim()).filter(Boolean);
  let h1Status;
  if (h1texts.length === 0) h1Status = { status: 'error', count: 0, values: [], message: 'H1 مفقود' };
  else if (h1texts.length > 1) h1Status = { status: 'warning', count: h1texts.length, values: h1texts, message: `${h1texts.length} عناوين H1 — يُفضل عنوان واحد فقط` };
  else h1Status = { status: 'good', count: 1, values: h1texts, message: 'H1 ممتاز' };

  return {
    h1: h1Status,
    headingsStructure: {
      status: h2matches.length > 0 ? 'good' : 'warning',
      h1: h1texts.length,
      h2: h2matches.length,
      h3: h3matches.length,
      message: h2matches.length === 0 ? 'لا يوجد H2 — أضف عناوين فرعية' : `${h1texts.length} H1، ${h2matches.length} H2، ${h3matches.length} H3`,
    }
  };
}

function checkImages(html) {
  const imgTags = [...html.matchAll(/<img([^>]*)>/gi)];
  const total = imgTags.length;
  if (total === 0) return { images: { status: 'good', total: 0, withAlt: 0, withoutAlt: 0, message: 'لا توجد صور' } };

  let withAlt = 0, withoutAlt = 0, emptyAlt = 0;
  for (const img of imgTags) {
    const attrs = img[1];
    const altMatch = attrs.match(/alt=["']([^"']*)["']/i);
    if (!altMatch) withoutAlt++;
    else if (altMatch[1].trim() === '') emptyAlt++;
    else withAlt++;
  }

  const missing = withoutAlt + emptyAlt;
  const status = missing === 0 ? 'good' : missing > total / 2 ? 'error' : 'warning';
  return {
    images: {
      status, total, withAlt, withoutAlt, emptyAlt,
      message: missing === 0
        ? `جميع الصور (${total}) تحتوي على Alt Text`
        : `${missing} من ${total} صورة تفتقر لـ Alt Text`
    }
  };
}

function checkHttps(targetUrl, finalUrl, response) {
  const isHttps = targetUrl.protocol === 'https:';
  const finalHttps = finalUrl.startsWith('https://');
  return {
    https: {
      status: isHttps && finalHttps ? 'good' : 'error',
      isHttps,
      finalHttps,
      message: isHttps ? 'HTTPS مفعّل ✓' : 'الموقع لا يستخدم HTTPS — مشكلة أمنية وSEO'
    }
  };
}

function checkCanonical(html, finalUrl) {
  const match = html.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']*)["']/i)
               || html.match(/<link[^>]+href=["']([^"']*)["'][^>]+rel=["']canonical["']/i);
  if (!match) return { canonical: { status: 'warning', value: null, message: 'Canonical URL مفقود — يُنصح بإضافته' } };
  return { canonical: { status: 'good', value: match[1], message: 'Canonical URL موجود' } };
}

function checkRobotsMeta(html) {
  const match = html.match(/<meta[^>]+name=["']robots["'][^>]+content=["']([^"']*)["']/i)
               || html.match(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']robots["']/i);
  if (!match) return { robotsMeta: { status: 'good', value: null, message: 'لا يوجد robots meta — الافتراضي index, follow' } };
  const content = match[1].toLowerCase();
  const isBlocked = content.includes('noindex') || content.includes('nofollow');
  return {
    robotsMeta: {
      status: isBlocked ? 'error' : 'good',
      value: match[1],
      message: isBlocked ? `⚠️ الصفحة محجوبة: ${match[1]}` : `robots: ${match[1]}`
    }
  };
}

function checkOpenGraph(html) {
  const ogTitle = html.match(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']*)["']/i);
  const ogDesc  = html.match(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']*)["']/i);
  const ogImage = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']*)["']/i);

  const hasAll = ogTitle && ogDesc && ogImage;
  const hasSome = ogTitle || ogDesc || ogImage;

  return {
    openGraph: {
      status: hasAll ? 'good' : hasSome ? 'warning' : 'warning',
      hasTitle: !!ogTitle,
      hasDescription: !!ogDesc,
      hasImage: !!ogImage,
      message: hasAll ? 'Open Graph كامل ✓'
        : hasSome ? `Open Graph ناقص — مفقود: ${[!ogTitle&&'og:title', !ogDesc&&'og:description', !ogImage&&'og:image'].filter(Boolean).join(', ')}`
        : 'Open Graph غير موجود — يؤثر على مشاركات السوشيال ميديا'
    }
  };
}

function checkStructuredData(html) {
  const jsonLd = html.match(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi);
  return {
    structuredData: {
      status: jsonLd && jsonLd.length > 0 ? 'good' : 'warning',
      count: jsonLd ? jsonLd.length : 0,
      message: jsonLd && jsonLd.length > 0
        ? `${jsonLd.length} JSON-LD Schema موجود`
        : 'لا يوجد Structured Data — أضف JSON-LD Schema'
    }
  };
}

function checkLang(html) {
  const match = html.match(/<html[^>]+lang=["']([^"']*)["']/i);
  return {
    lang: {
      status: match ? 'good' : 'warning',
      value: match ? match[1] : null,
      message: match ? `lang="${match[1]}" ✓` : 'lang attribute مفقود في <html>'
    }
  };
}

function checkViewport(html) {
  const match = html.match(/<meta[^>]+name=["']viewport["'][^>]+content=["']([^"']*)["']/i)
               || html.match(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']viewport["']/i);
  return {
    viewport: {
      status: match ? 'good' : 'error',
      value: match ? match[1] : null,
      message: match ? 'Viewport مضبوط للجوال ✓' : 'Viewport مفقود — الموقع لن يظهر صحيحاً على الجوال'
    }
  };
}

function checkWordCount(html) {
  const bodyMatch = html.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  if (!bodyMatch) return { wordCount: { status: 'warning', count: 0, message: 'تعذّر حساب الكلمات' } };
  const text = stripTags(bodyMatch[1]).replace(/\s+/g, ' ').trim();
  const words = text.split(' ').filter(w => w.length > 2).length;
  return {
    wordCount: {
      status: words >= 300 ? 'good' : words >= 100 ? 'warning' : 'error',
      count: words,
      message: words >= 300 ? `${words} كلمة — محتوى كافٍ`
        : words >= 100 ? `${words} كلمة — المحتوى قليل، يُنصح بـ 300+ كلمة`
        : `${words} كلمة — المحتوى شحيح جداً`
    }
  };
}

// ═══════════════════════════════════════════════
//  ✨ NEW: TWITTER CARDS CHECK
// ═══════════════════════════════════════════════
function checkTwitterCards(html) {
  const card    = html.match(/<meta[^>]+name=[\"']twitter:card[\"'][^>]+content=[\"']([^\"']*)[\"']/i);
  const title   = html.match(/<meta[^>]+name=[\"']twitter:title[\"'][^>]+content=[\"']([^\"']*)[\"']/i);
  const desc    = html.match(/<meta[^>]+name=[\"']twitter:description[\"'][^>]+content=[\"']([^\"']*)[\"']/i);
  const image   = html.match(/<meta[^>]+name=[\"']twitter:image[\"'][^>]+content=[\"']([^\"']*)[\"']/i);
  const site    = html.match(/<meta[^>]+name=[\"']twitter:site[\"'][^>]+content=[\"']([^\"']*)[\"']/i);

  const hasCard  = !!card;
  const hasTitle = !!title;
  const hasDesc  = !!desc;
  const hasImage = !!image;
  const hasAll   = hasCard && hasTitle && hasDesc && hasImage;
  const hasSome  = hasCard || hasTitle || hasDesc;

  const missing = [
    !hasCard  && 'twitter:card',
    !hasTitle && 'twitter:title',
    !hasDesc  && 'twitter:description',
    !hasImage && 'twitter:image',
  ].filter(Boolean);

  return {
    twitterCards: {
      status     : hasAll ? 'good' : hasSome ? 'warning' : 'warning',
      hasCard,
      hasTitle,
      hasDescription: hasDesc,
      hasImage,
      hasSite    : !!site,
      cardType   : card?.[1] ?? null,
      message    : hasAll
        ? `Twitter Cards كاملة ✓ (${card[1]})`
        : hasSome
        ? `Twitter Cards ناقصة — مفقود: ${missing.join(', ')}`
        : 'Twitter Cards غير موجودة — أضفها لتحسين المشاركة على X/Twitter',
    }
  };
}

// ═══════════════════════════════════════════════
//  ✨ NEW: LINKS CHECK (internal / external)
// ═══════════════════════════════════════════════
function checkLinks(html, finalUrl) {
  let base;
  try { base = new URL(finalUrl); } catch { base = null; }

  const linkMatches = [...html.matchAll(/<a[^>]+href=[\"']([^\"'#][^\"']*)[\"'][^>]*>/gi)];
  let internal = 0, external = 0, nofollowCount = 0;
  const allHrefs = [];

  for (const m of linkMatches) {
    const href  = m[1]?.trim();
    const attrs = m[0];
    if (!href || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) continue;

    let absolute;
    try {
      absolute = new URL(href, finalUrl).href;
    } catch { continue; }

    const isInternal = base && new URL(absolute).hostname === base.hostname;
    if (isInternal) internal++;
    else external++;

    if (/rel=[\"'][^\"']*nofollow[^\"']*[\"']/i.test(attrs)) nofollowCount++;
    allHrefs.push({ href: absolute, isInternal });
  }

  const total = internal + external;

  return {
    links: {
      status    : total === 0 ? 'warning' : 'good',
      total,
      internal,
      external,
      nofollow  : nofollowCount,
      message   : total === 0
        ? 'لا توجد روابط في الصفحة'
        : `${total} رابط: ${internal} داخلي، ${external} خارجي${nofollowCount > 0 ? `، ${nofollowCount} nofollow` : ''}`,
    }
  };
}

// ═══════════════════════════════════════════════
//  ✨ NEW: BROKEN LINKS CHECK
// ═══════════════════════════════════════════════
async function checkBrokenLinks(html, finalUrl) {
  // Extract up to MAX_LINKS_TO_CHECK unique links
  const linkMatches = [...html.matchAll(/<a[^>]+href=[\"']([^\"'#][^\"']*)[\"']/gi)];
  const seen  = new Set();
  const toCheck = [];

  for (const m of linkMatches) {
    const href = m[1]?.trim();
    if (!href || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) continue;
    let absolute;
    try { absolute = new URL(href, finalUrl).href; } catch { continue; }
    if (seen.has(absolute)) continue;
    seen.add(absolute);
    toCheck.push(absolute);
    if (toCheck.length >= CONFIG.MAX_LINKS_TO_CHECK) break;
  }

  if (toCheck.length === 0) {
    return { brokenLinks: { status: 'good', broken: [], checked: 0, message: 'لا توجد روابط للفحص' } };
  }

  // HEAD requests in parallel (with timeout)
  const results = await Promise.allSettled(
    toCheck.map(async href => {
      const ctrl = new AbortController();
      const t    = setTimeout(() => ctrl.abort(), 8000);
      try {
        const r = await fetch(href, {
          method : 'HEAD',
          signal : ctrl.signal,
          headers: { 'User-Agent': 'SEOCheckerBot/2.0' },
          redirect: 'follow',
        });
        clearTimeout(t);
        return { href, status: r.status, ok: r.status < 400 };
      } catch {
        clearTimeout(t);
        return { href, status: 0, ok: false };
      }
    })
  );

  const checked = results.length;
  const broken  = results
    .filter(r => r.status === 'fulfilled' && !r.value.ok)
    .map(r => ({ href: r.value.href, status: r.value.status }));

  return {
    brokenLinks: {
      status : broken.length === 0 ? 'good' : broken.length <= 2 ? 'warning' : 'error',
      broken,
      checked,
      message: broken.length === 0
        ? `فُحص ${checked} رابط — لا توجد روابط مكسورة ✓`
        : `${broken.length} رابط مكسور من أصل ${checked} رابط تم فحصها`,
    }
  };
}

// ═══════════════════════════════════════════════
//  ✨ NEW: MULTI-PAGE CRAWL
// ═══════════════════════════════════════════════
async function crawlSite(startUrl, env) {
  const base    = `${startUrl.protocol}//${startUrl.host}`;
  const visited = new Set();
  const queue   = [startUrl.href];
  const pages   = [];

  while (queue.length > 0 && pages.length < CONFIG.MAX_CRAWL_PAGES) {
    const pageUrl = queue.shift();
    if (visited.has(pageUrl)) continue;
    visited.add(pageUrl);

    // Single fetch — reuse HTML for both analysis and link discovery
    const ctrl    = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), CONFIG.FETCH_TIMEOUT_MS);
    let html = '';

    try {
      const r = await fetch(pageUrl, {
        signal  : ctrl.signal,
        headers : { 'User-Agent': 'Mozilla/5.0 (compatible; SEOCheckerBot/2.0)', Accept: 'text/html,*/*;q=0.8' },
        redirect: 'follow',
      });
      clearTimeout(timeout);

      // Size guard
      const reader = r.body.getReader();
      const chunks = [];
      let   total  = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > CONFIG.MAX_HTML_BYTES) { reader.cancel(); break; }
        chunks.push(value);
      }
      const buf = new Uint8Array(chunks.reduce((a, c) => a + c.byteLength, 0));
      let offset = 0;
      for (const c of chunks) { buf.set(c, offset); offset += c.byteLength; }
      html = new TextDecoder('utf-8', { fatal: false }).decode(buf);

      // Quick SEO metrics from HTML
      const titleMatch  = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
      const title       = titleMatch ? titleMatch[1].trim().substring(0, 80) : null;
      const hasTitle    = !!title && title.length > 0;
      const hasDesc     = /<meta[^>]+name=["']description["']/i.test(html);
      const hasH1       = /<h1[\s/>]/i.test(html);
      const hasViewport = /<meta[^>]+name=["']viewport["']/i.test(html);
      const isHttps     = pageUrl.startsWith('https://');
      const passCount   = [hasTitle, hasDesc, hasH1, hasViewport, isHttps].filter(Boolean).length;
      const errorCount  = 5 - passCount;

      pages.push({
        url   : pageUrl,
        score : Math.round((passCount / 5) * 100),
        title,
        issues: errorCount,
        errors: errorCount,
      });

      // Discover internal links for queue
      const linkMatches = [...html.matchAll(/<a[^>]+href=["']([^"'#][^"']*)['"]/gi)];
      for (const m of linkMatches) {
        try {
          const abs = new URL(m[1], pageUrl).href;
          if (abs.startsWith(base) && !visited.has(abs) && !queue.includes(abs)) {
            queue.push(abs);
          }
        } catch { /* skip malformed */ }
      }

    } catch { clearTimeout(timeout); /* skip failed pages */ }
  }

  const avgScore = pages.length > 0
    ? Math.round(pages.reduce((s, p) => s + p.score, 0) / pages.length)
    : 0;

  return {
    startUrl     : startUrl.href,
    pagesFound   : visited.size,
    pagesCrawled : pages.length,
    avgScore,
    pages,
    crawledAt    : new Date().toISOString(),
  };
}
async function checkPageSpeed(targetUrl, apiKey) {
  if (!apiKey) return null;

  const base = 'https://www.googleapis.com/pagespeedonline/v5/runPagespeed';
  const params = new URLSearchParams({
    url: targetUrl.href,
    key: apiKey,
    strategy: 'mobile',
    category: 'performance',
  });

  const r = await fetch(`${base}?${params}`, {
    headers: { 'Accept': 'application/json' }
  });

  if (!r.ok) return null;

  const data = await r.json();
  const cats = data.lighthouseResult?.categories;
  const audits = data.lighthouseResult?.audits;

  if (!cats || !audits) return null;

  const perf = Math.round((cats.performance?.score ?? 0) * 100);

  // Core Web Vitals
  const lcp  = audits['largest-contentful-paint'];
  const fid  = audits['max-potential-fid'] || audits['total-blocking-time'];
  const cls  = audits['cumulative-layout-shift'];
  const fcp  = audits['first-contentful-paint'];
  const ttfb = audits['server-response-time'];
  const si   = audits['speed-index'];

  function vitalsStatus(score) {
    if (score === null || score === undefined) return 'warning';
    if (score >= 0.9) return 'good';
    if (score >= 0.5) return 'warning';
    return 'error';
  }

  return {
    performanceScore: perf,
    status: perf >= 90 ? 'good' : perf >= 50 ? 'warning' : 'error',
    strategy: 'mobile',
    vitals: {
      lcp:  { value: lcp?.displayValue  ?? 'N/A', score: lcp?.score,  status: vitalsStatus(lcp?.score),  label: 'LCP'  },
      fid:  { value: fid?.displayValue  ?? 'N/A', score: fid?.score,  status: vitalsStatus(fid?.score),  label: 'TBT'  },
      cls:  { value: cls?.displayValue  ?? 'N/A', score: cls?.score,  status: vitalsStatus(cls?.score),  label: 'CLS'  },
      fcp:  { value: fcp?.displayValue  ?? 'N/A', score: fcp?.score,  status: vitalsStatus(fcp?.score),  label: 'FCP'  },
      ttfb: { value: ttfb?.displayValue ?? 'N/A', score: ttfb?.score, status: vitalsStatus(ttfb?.score), label: 'TTFB' },
      si:   { value: si?.displayValue   ?? 'N/A', score: si?.score,   status: vitalsStatus(si?.score),   label: 'Speed Index' },
    },
  };
}

async function checkRobotsTxt(targetUrl) {
  try {
    const r = await fetch(`${targetUrl.protocol}//${targetUrl.host}/robots.txt`, {
      headers: { 'User-Agent': 'SEOCheckerBot/1.0' }
    });
    if (r.status === 200) {
      const text = await r.text();
      const hasSitemap = /sitemap:/i.test(text);
      return { robotsTxt: { status: 'good', exists: true, hasSitemap, message: `robots.txt موجود${hasSitemap ? ' ويحتوي على Sitemap' : ''}` } };
    }
    return { robotsTxt: { status: 'warning', exists: false, message: 'robots.txt غير موجود (404)' } };
  } catch {
    return { robotsTxt: { status: 'warning', exists: false, message: 'تعذّر قراءة robots.txt' } };
  }
}

async function checkSitemap(targetUrl, html) {
  // Try common locations
  const candidates = [
    `${targetUrl.protocol}//${targetUrl.host}/sitemap.xml`,
    `${targetUrl.protocol}//${targetUrl.host}/sitemap_index.xml`,
  ];

  // Also check if mentioned in robots.txt (we extract from HTML for now)
  const sitemapInHtml = html.match(/sitemap[_-]?index?\.xml/i);

  for (const candidate of candidates) {
    try {
      const r = await fetch(candidate, { headers: { 'User-Agent': 'SEOCheckerBot/1.0' } });
      if (r.status === 200) {
        const text = await r.text();
        const urlCount = (text.match(/<url>/gi) || []).length;
        return { sitemap: { status: 'good', exists: true, url: candidate, urlCount, message: `Sitemap موجود${urlCount > 0 ? ` — ${urlCount} رابط` : ''}` } };
      }
    } catch { /* continue */ }
  }

  return { sitemap: { status: 'error', exists: false, message: 'Sitemap.xml غير موجود — أضفه لمساعدة Google على الفهرسة' } };
}

// ═══════════════════════════════════════════════
//  PROFESSIONAL SCORING SYSTEM — 6 CATEGORIES
// ═══════════════════════════════════════════════
function calcScore(checks) {

  // ── Category definitions ──
  const CATEGORIES = {
    technical: {
      label: 'Technical SEO',
      icon: '🔧',
      weight: 0.23,
      checks: {
        https:      { good: 20, warning: 5,  error: 0 },
        viewport:   { good: 15, warning: 0,  error: 0 },
        robotsTxt:  { good: 15, warning: 8,  error: 0 },
        sitemap:    { good: 20, warning: 0,  error: 0 },
        canonical:  { good: 15, warning: 8,  error: 0 },
        lang:       { good: 15, warning: 5,  error: 0 },
      }
    },
    onpage: {
      label: 'On-Page SEO',
      icon: '📝',
      weight: 0.22,
      checks: {
        title:           { good: 30, warning: 15, error: 0 },
        metaDescription: { good: 25, warning: 12, error: 0 },
        h1:              { good: 25, warning: 12, error: 0 },
        wordCount:       { good: 20, warning: 10, error: 0 },
      }
    },
    performance: {
      label: 'Performance',
      icon: '⚡',
      weight: 0.20,
      checks: {
        // populated from PageSpeed if available, else from basic checks
        images: { good: 50, warning: 25, error: 5 },
      }
    },
    mobile: {
      label: 'Mobile & UX',
      icon: '📱',
      weight: 0.15,
      checks: {
        viewport:        { good: 60, warning: 0,  error: 0 },
        images:          { good: 40, warning: 20, error: 5 },
      }
    },
    social: {
      label: 'Social SEO',
      icon: '🌐',
      weight: 0.10,
      checks: {
        openGraph    : { good: 50, warning: 25, error: 0 },
        twitterCards : { good: 30, warning: 15, error: 0 },
        lang         : { good: 20, warning: 10, error: 0 },
      }
    },
    structured: {
      label: 'Structured Data',
      icon: '🗂️',
      weight: 0.05,
      checks: {
        structuredData: { good: 100, warning: 40, error: 0 },
      }
    },
    links: {
      label: 'Links',
      icon: '🔗',
      weight: 0.05,
      checks: {
        links       : { good: 50, warning: 25, error: 0 },
        brokenLinks : { good: 50, warning: 20, error: 0 },
      }
    },
  };

  const categories = {};
  let totalScore = 0;

  for (const [catKey, cat] of Object.entries(CATEGORIES)) {
    let catRaw = 0;
    let catMax = 0;
    let passed = 0, warnings = 0, errors = 0;
    const items = {};

    for (const [checkKey, weights] of Object.entries(cat.checks)) {
      const check = checks[checkKey];
      if (!check) continue;
      const pts = weights[check.status] ?? 0;
      const max = weights.good;
      catRaw += pts;
      catMax += max;
      items[checkKey] = { status: check.status, points: pts, max };
      if (check.status === 'good')    passed++;
      else if (check.status === 'warning') warnings++;
      else errors++;
    }

    const catScore = catMax > 0 ? Math.round((catRaw / catMax) * 100) : 0;
    const weighted = catScore * cat.weight;
    totalScore += weighted;

    categories[catKey] = {
      label:    cat.label,
      icon:     cat.icon,
      score:    catScore,
      weighted: Math.round(weighted),
      weight:   Math.round(cat.weight * 100),
      passed,
      warnings,
      errors,
      status:   catScore >= 80 ? 'good' : catScore >= 50 ? 'warning' : 'error',
      items,
    };
  }

  const finalScore = Math.min(100, Math.round(totalScore));

  // Legacy flat breakdown for backward compat
  const breakdown = {};
  for (const cat of Object.values(categories)) {
    for (const [k, v] of Object.entries(cat.items)) {
      breakdown[k] = v;
    }
  }

  // Summary counts
  const summary = {
    passed:   Object.values(categories).reduce((a,c) => a + c.passed,   0),
    warnings: Object.values(categories).reduce((a,c) => a + c.warnings, 0),
    errors:   Object.values(categories).reduce((a,c) => a + c.errors,   0),
  };

  return { score: finalScore, breakdown, categories, summary };
}

// ═══════════════════════════════════════════════
//  BUILD ISSUES LIST
// ═══════════════════════════════════════════════
function buildIssues(checks) {
  const issues = [];
  for (const [key, check] of Object.entries(checks)) {
    if (!check || check.status === 'good') continue;
    issues.push({
      key,
      severity: check.status,
      message: check.message,
      value: check.value ?? null,
    });
  }
  // Sort: error first, then warning
  issues.sort((a, b) => (a.severity === 'error' ? -1 : 1));
  return issues;
}

// ═══════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════
function json(data, status = 200, corsHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
  });
}

function stripTags(str) {
  return str.replace(/<[^>]+>/g, ' ').replace(/&[^;]+;/g, ' ');
}

function decode(str) {
  return str
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'")
    .replace(/&nbsp;/g, ' ');
}
