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
        return json(
          { error: `تجاوزت الحد المسموح. حاول بعد ${limit.resetIn} ثانية.` },
          429,
          { ...cors, 'Retry-After': String(limit.resetIn) }
        );
      }

      const target = url.searchParams.get('url');
      if (!target) return json({ error: 'يجب إرسال url' }, 400, cors);

      let targetUrl;
      try {
        targetUrl = new URL(target.startsWith('http') ? target : 'https://' + target);
      } catch {
        return json({ error: 'رابط غير صالح' }, 400, cors);
      }

      // ── Block non-http(s) and internal networks ──
      if (!ALLOWED_PROTOCOLS.has(targetUrl.protocol)) {
        return json({ error: 'بروتوكول غير مسموح به — يُقبل http و https فقط' }, 400, cors);
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

  // ── Track redirect chain separately (lightweight, manual redirect mode) ──
  const redirectChain = await traceRedirectChain(targetUrl.href);

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
    // 13. Twitter Cards
    ...checkTwitterCards(html),
    // 14. Links (internal/external)
    ...checkLinks(html, finalUrl),
    // 15. Hreflang
    ...checkHreflang(html),
    // 16. Charset
    ...checkCharset(html),
    // 17. Favicon
    ...checkFavicon(html, finalUrl),
    // 18. Image dimensions (CLS / lazy loading)
    ...checkImageDimensions(html),
    // 19. Resource hints (preconnect, dns-prefetch)
    ...checkResourceHints(html),
    // 20. Render-blocking resources (script defer/async, CSS)
    ...checkRenderBlocking(html),
    // 21. Text / HTML ratio
    ...checkTextHtmlRatio(html),
    // 22. Canonical validity (self vs cross)
    ...checkCanonicalValidity(html, finalUrl),
    // 23. Structured Data types
    ...checkStructuredDataTypes(html),
    // 24. X-Robots-Tag header
    ...checkXRobotsTag(response),
    // 25. Keyword Density & Stuffing
    ...checkKeywordDensity(html),
    // 26. Title/H1 Keyword Match
    ...checkTitleH1Match(html),
    // 27. Readability
    ...checkReadability(html),
    // 28. Duplicate Title/H1
    ...checkDuplicateTitleH1(html),
    // 29. Content Position in HTML
    ...checkContentPosition(html),
    // 30. Security Headers
    ...checkSecurityHeaders(response),
    // 31. Redirect Chain
    ...checkRedirectChain(redirectChain),
    // 32. AMP
    ...checkAmp(html),
    // 33. PWA / Manifest
    ...checkPwa(html),
    // 34. Mixed Content
    ...checkMixedContent(html, finalUrl),
    // 35. HTTP Protocol Version
    ...checkHttpProtocol(response),
    // 36. Cookie Security
    ...checkCookieSecurity(response),
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

// ═══════════════════════════════════════════════
//  DEEP CHECKS — Professional Level
// ═══════════════════════════════════════════════

// 15. HREFLANG
function checkHreflang(html) {
  const tags = [...html.matchAll(/<link[^>]+rel=["']alternate["'][^>]+hreflang=["']([^"']*)["'][^>]*>/gi)];
  const altTags = [...html.matchAll(/<link[^>]+hreflang=["']([^"']*)["'][^>]+rel=["']alternate["'][^>]*>/gi)];
  const all = [...new Set([...tags, ...altTags].map(m => m[1]))];

  if (all.length === 0) {
    return { hreflang: { status: 'warning', count: 0, values: [], message: 'hreflang غير موجود — أضفه إذا كان الموقع متعدد اللغات' } };
  }

  const hasXDefault = all.some(v => v === 'x-default');
  return {
    hreflang: {
      status: hasXDefault ? 'good' : 'warning',
      count: all.length,
      values: all,
      hasXDefault,
      message: hasXDefault
        ? `hreflang موجود — ${all.length} لغة/منطقة تشمل x-default`
        : `hreflang موجود (${all.length}) لكن يفتقر x-default`,
    }
  };
}

// 16. CHARSET
function checkCharset(html) {
  const utf8    = /<meta[^>]+charset=["']?utf-8["']?/i.test(html);
  const anyChar = /<meta[^>]+charset=/i.test(html);
  const httpEq  = /<meta[^>]+http-equiv=["']content-type["'][^>]+content=["'][^"']*charset/i.test(html);

  return {
    charset: {
      status  : utf8 || httpEq ? 'good' : anyChar ? 'warning' : 'error',
      isUtf8  : utf8,
      message : utf8 ? 'Charset UTF-8 ✓'
        : httpEq ? 'Charset محدد عبر http-equiv (يُفضل <meta charset="utf-8">)'
        : anyChar ? 'Charset محدد لكن ليس UTF-8 — تحقق من التوافق'
        : 'Charset مفقود — أضف <meta charset="utf-8">',
    }
  };
}

// 17. FAVICON
function checkFavicon(html, finalUrl) {
  const shortcut = /<link[^>]+rel=["'][^"']*(?:shortcut icon|icon)[^"']*["'][^>]*>/i.test(html);
  const apple    = /<link[^>]+rel=["']apple-touch-icon["'][^>]*>/i.test(html);
  const svg      = /<link[^>]+type=["']image\/svg\+xml["'][^>]*>/i.test(html);

  // Extract favicon href
  const hrefMatch = html.match(/<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']*)["']/i)
                 || html.match(/<link[^>]+href=["']([^"']*)["'][^>]+rel=["'][^"']*icon[^"']*["']/i);
  const faviconUrl = hrefMatch ? hrefMatch[1] : null;

  const hasAny = shortcut || apple || svg;
  return {
    favicon: {
      status  : hasAny ? 'good' : 'warning',
      hasIcon  : shortcut,
      hasApple : apple,
      hasSvg   : svg,
      url      : faviconUrl,
      message  : hasAny
        ? `Favicon موجود${apple ? ' + Apple Touch Icon' : ''}${svg ? ' + SVG' : ''}`
        : 'Favicon مفقود — أضف <link rel="icon"> لتحسين التعرف على العلامة التجارية',
    }
  };
}

// 18. IMAGE DIMENSIONS & LAZY LOADING
function checkImageDimensions(html) {
  const imgs = [...html.matchAll(/<img([^>]*)>/gi)];
  const total = imgs.length;
  if (total === 0) return { imageDimensions: { status: 'good', total: 0, message: 'لا توجد صور' } };

  let missingDims = 0, lazyCount = 0, noLazy = 0;
  for (const img of imgs) {
    const attrs = img[1];
    const hasWidth  = /\bwidth=["']?\d+/i.test(attrs);
    const hasHeight = /\bheight=["']?\d+/i.test(attrs);
    if (!hasWidth || !hasHeight) missingDims++;
    if (/loading=["']lazy["']/i.test(attrs)) lazyCount++;
    else noLazy++;
  }

  const dimStatus = missingDims === 0 ? 'good' : missingDims > total / 2 ? 'error' : 'warning';
  return {
    imageDimensions: {
      status     : dimStatus,
      total,
      missingDims,
      lazyCount,
      noLazyCount: noLazy,
      message    : missingDims === 0
        ? `جميع الصور (${total}) تحتوي على أبعاد — لا مشكلة CLS`
        : `${missingDims} من ${total} صورة بدون width/height — قد يسبب CLS`,
      lazyMessage: lazyCount > 0
        ? `${lazyCount} صورة تستخدم lazy loading`
        : 'لا توجد صور بـ loading="lazy" — أضفها لتسريع التحميل',
    }
  };
}

// 19. RESOURCE HINTS
function checkResourceHints(html) {
  const preconnect   = [...html.matchAll(/<link[^>]+rel=["']preconnect["'][^>]*>/gi)];
  const dnsPrefetch  = [...html.matchAll(/<link[^>]+rel=["']dns-prefetch["'][^>]*>/gi)];
  const preload      = [...html.matchAll(/<link[^>]+rel=["']preload["'][^>]*>/gi)];
  const prefetch     = [...html.matchAll(/<link[^>]+rel=["']prefetch["'][^>]*>/gi)];

  const total = preconnect.length + dnsPrefetch.length + preload.length;
  return {
    resourceHints: {
      status        : total > 0 ? 'good' : 'warning',
      preconnect    : preconnect.length,
      dnsPrefetch   : dnsPrefetch.length,
      preload       : preload.length,
      prefetch      : prefetch.length,
      message       : total > 0
        ? `Resource Hints موجودة: ${preconnect.length} preconnect، ${dnsPrefetch.length} dns-prefetch، ${preload.length} preload`
        : 'لا توجد Resource Hints — أضف preconnect/dns-prefetch لموارد خارجية (fonts, CDN)',
    }
  };
}

// 20. RENDER-BLOCKING RESOURCES
function checkRenderBlocking(html) {
  // CSS in <head> without media attribute (blocking)
  const headMatch = html.match(/<head[^>]*>([\s\S]*?)<\/head>/i);
  const head = headMatch ? headMatch[1] : '';

  const blockingCss    = [...head.matchAll(/<link[^>]+rel=["']stylesheet["'][^>]*>/gi)]
    .filter(m => !/media=["']print["']/i.test(m[0]) && !/media=["']none["']/i.test(m[0]));

  const scriptTags     = [...html.matchAll(/<script([^>]*)>/gi)];
  const blockingJs     = scriptTags.filter(m =>
    !m[1].includes('async') && !m[1].includes('defer') &&
    !m[1].includes('type="module"') && !m[1].includes("type='module'") &&
    !m[1].includes('type="application/ld+json"') && m[1].includes('src=')
  );
  const deferredJs     = scriptTags.filter(m => /\bdefer\b/i.test(m[1]) && m[1].includes('src='));
  const asyncJs        = scriptTags.filter(m => /\basync\b/i.test(m[1]) && m[1].includes('src='));

  const blockingCount = blockingCss.length + blockingJs.length;
  return {
    renderBlocking: {
      status        : blockingCount === 0 ? 'good' : blockingCount <= 3 ? 'warning' : 'error',
      blockingCss   : blockingCss.length,
      blockingJs    : blockingJs.length,
      deferredJs    : deferredJs.length,
      asyncJs       : asyncJs.length,
      message       : blockingCount === 0
        ? `لا توجد موارد تعطّل الرندر — ${deferredJs.length} defer، ${asyncJs.length} async`
        : `${blockingCount} مورد يعطّل الرندر (${blockingCss.length} CSS، ${blockingJs.length} JS بدون defer/async)`,
    }
  };
}

// 21. TEXT / HTML RATIO
function checkTextHtmlRatio(html) {
  const htmlBytes = html.length;
  const text      = stripTags(html).replace(/\s+/g, ' ').trim();
  const textBytes = text.length;
  const ratio     = htmlBytes > 0 ? Math.round((textBytes / htmlBytes) * 100) : 0;

  return {
    textHtmlRatio: {
      status  : ratio >= 15 ? 'good' : ratio >= 8 ? 'warning' : 'error',
      ratio,
      textBytes,
      htmlBytes,
      message : ratio >= 15
        ? `نسبة النص إلى HTML: ${ratio}% — ممتازة`
        : ratio >= 8
        ? `نسبة النص إلى HTML: ${ratio}% — منخفضة (المثالي 15%+)`
        : `نسبة النص إلى HTML: ${ratio}% — منخفضة جداً، الصفحة ثقيلة بالكود`,
    }
  };
}

// 22. CANONICAL VALIDITY
function checkCanonicalValidity(html, finalUrl) {
  const match = html.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']*)["']/i)
             || html.match(/<link[^>]+href=["']([^"']*)["'][^>]+rel=["']canonical["']/i);

  if (!match) return { canonicalValidity: { status: 'warning', message: 'لا يوجد canonical — تحقق من checkCanonical' } };

  const canonicalUrl = match[1].trim();
  let isSelf = false;
  try {
    const canonical = new URL(canonicalUrl, finalUrl);
    const current   = new URL(finalUrl);
    isSelf = canonical.href === current.href ||
             canonical.href.replace(/\/$/, '') === current.href.replace(/\/$/, '');
  } catch { /* ignore */ }

  const isAbsolute = canonicalUrl.startsWith('http');
  const isEmpty    = canonicalUrl.length === 0;

  return {
    canonicalValidity: {
      status : isEmpty ? 'error' : !isAbsolute ? 'warning' : isSelf ? 'good' : 'warning',
      url    : canonicalUrl,
      isSelf,
      isAbsolute,
      message: isEmpty ? 'Canonical فارغ — مشكلة خطيرة'
        : !isAbsolute ? 'Canonical بـ URL نسبي — يُفضل URL مطلق'
        : isSelf ? 'Canonical يشير لنفس الصفحة (Self-referencing) ✓'
        : `Canonical يشير لصفحة مختلفة: ${canonicalUrl.substring(0, 60)}...`,
    }
  };
}

// 23. STRUCTURED DATA TYPES
function checkStructuredDataTypes(html) {
  const blocks = [...html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)];
  if (blocks.length === 0) return { structuredDataTypes: { status: 'warning', types: [], count: 0, message: 'لا يوجد JSON-LD Schema' } };

  const types   = [];
  const errors  = [];
  for (const block of blocks) {
    try {
      const parsed = JSON.parse(block[1]);
      const typeArr = Array.isArray(parsed) ? parsed : [parsed];
      for (const item of typeArr) {
        const t = item['@type'];
        if (t) types.push(Array.isArray(t) ? t.join('+') : t);
      }
    } catch (e) {
      errors.push('JSON-LD parse error: ' + e.message.substring(0, 50));
    }
  }

  const hasErrors  = errors.length > 0;
  const uniqueTypes = [...new Set(types)];

  // Bonus: check for high-value schema types
  const highValue = ['Article','Product','FAQPage','BreadcrumbList','LocalBusiness','WebSite','Review','HowTo','Event','Recipe'];
  const foundHighValue = uniqueTypes.filter(t => highValue.includes(t));

  return {
    structuredDataTypes: {
      status : hasErrors ? 'error' : types.length > 0 ? 'good' : 'warning',
      types  : uniqueTypes,
      count  : blocks.length,
      parseErrors: errors,
      highValueTypes: foundHighValue,
      message: hasErrors
        ? `${errors.length} JSON-LD يحتوي على أخطاء syntax`
        : uniqueTypes.length > 0
        ? `Schema Types: ${uniqueTypes.join(', ')}${foundHighValue.length > 0 ? ' ✓ (High-value)' : ''}`
        : `${blocks.length} JSON-LD موجود لكن بدون @type`,
    }
  };
}

// 24. X-ROBOTS-TAG HEADER
function checkXRobotsTag(response) {
  const header = response.headers.get('x-robots-tag') ?? response.headers.get('X-Robots-Tag');
  if (!header) return { xRobotsTag: { status: 'good', value: null, message: 'X-Robots-Tag غير موجود — الافتراضي index, follow' } };

  const lower     = header.toLowerCase();
  const isBlocked = lower.includes('noindex') || lower.includes('none');
  return {
    xRobotsTag: {
      status : isBlocked ? 'error' : 'good',
      value  : header,
      message: isBlocked
        ? `⚠️ X-Robots-Tag: ${header} — الصفحة محجوبة عن محركات البحث`
        : `X-Robots-Tag: ${header}`,
    }
  };
}


// ═══════════════════════════════════════════════
//  DEEP CHECKS — TIER 2 (On-Page Content + Technical)
// ═══════════════════════════════════════════════

// ── Helper: extract visible body text ──
function extractBodyText(html) {
  const bodyMatch = html.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  let body = bodyMatch ? bodyMatch[1] : html;
  // Strip script/style/noscript content entirely
  body = body.replace(/<(script|style|noscript)[^>]*>[\s\S]*?<\/\1>/gi, ' ');
  return stripTags(body).replace(/\s+/g, ' ').trim();
}

// 25. KEYWORD DENSITY & STUFFING
function checkKeywordDensity(html) {
  const text = extractBodyText(html);
  if (!text) return { keywordDensity: { status: 'warning', topKeywords: [], message: 'لا يوجد محتوى نصي لتحليله' } };

  // Arabic + Latin word tokenizer, strip common stopwords (en + ar minimal set)
  const STOPWORDS = new Set([
    'the','and','for','are','but','not','you','with','this','that','from','have','was','were','your',
    'في','من','على','إلى','عن','مع','هذا','هذه','التي','الذي','كان','كانت','أن','إن','لا','ما','هو','هي',
  ]);

  const words = text.toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, ' ')
    .split(/\s+/)
    .filter(w => w.length > 2 && !STOPWORDS.has(w));

  const total = words.length;
  if (total === 0) return { keywordDensity: { status: 'warning', topKeywords: [], message: 'لا يمكن استخراج كلمات كافية' } };

  const freq = {};
  for (const w of words) freq[w] = (freq[w] || 0) + 1;

  const sorted = Object.entries(freq)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([word, count]) => ({ word, count, density: +((count / total) * 100).toFixed(1) }));

  const maxDensity = sorted[0]?.density ?? 0;
  const isStuffing = maxDensity > 5;

  return {
    keywordDensity: {
      status : isStuffing ? 'warning' : 'good',
      totalWords: total,
      topKeywords: sorted,
      message: isStuffing
        ? `⚠️ كلمة "${sorted[0].word}" بنسبة ${maxDensity}% — قد تُعتبر keyword stuffing (الأمثل أقل من 3%)`
        : `كثافة الكلمات طبيعية — أعلى كلمة "${sorted[0]?.word ?? '-'}" بنسبة ${maxDensity}%`,
    }
  };
}

// 26. TITLE / H1 KEYWORD MATCH
function checkTitleH1Match(html) {
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const h1Match    = html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i);

  const title = titleMatch ? decode(stripTags(titleMatch[1])).trim().toLowerCase() : '';
  const h1    = h1Match    ? decode(stripTags(h1Match[1])).trim().toLowerCase()    : '';

  if (!title || !h1) {
    return { titleH1Match: { status: 'warning', message: 'تعذّر المقارنة — Title أو H1 مفقود' } };
  }

  const titleWords = new Set(title.split(/\s+/).filter(w => w.length > 3));
  const h1Words    = new Set(h1.split(/\s+/).filter(w => w.length > 3));
  const shared     = [...titleWords].filter(w => h1Words.has(w));
  const overlapPct = titleWords.size > 0 ? Math.round((shared.length / titleWords.size) * 100) : 0;

  return {
    titleH1Match: {
      status : overlapPct >= 30 ? 'good' : 'warning',
      overlapPercent: overlapPct,
      sharedWords: shared,
      message: overlapPct >= 30
        ? `تطابق Title/H1 جيد (${overlapPct}%) — إشارة موضوعية قوية`
        : `تطابق Title/H1 ضعيف (${overlapPct}%) — قد يُربك محركات البحث حول موضوع الصفحة`,
    }
  };
}

// 27. READABILITY (simplified Flesch-like heuristic)
function checkReadability(html) {
  const text = extractBodyText(html);
  if (!text || text.length < 50) {
    return { readability: { status: 'warning', message: 'نص قصير جداً لتحليل القابلية للقراءة' } };
  }

  const sentences = text.split(/[.!?؟،۔]+/).filter(s => s.trim().length > 5);
  const words      = text.split(/\s+/).filter(Boolean);
  const sentCount  = sentences.length || 1;
  const wordCount  = words.length || 1;
  const avgWordsPerSentence = +(wordCount / sentCount).toFixed(1);

  // Heuristic: very long sentences hurt readability regardless of language
  let status, message;
  if (avgWordsPerSentence <= 20) {
    status  = 'good';
    message = `متوسط ${avgWordsPerSentence} كلمة/جملة — سهل القراءة`;
  } else if (avgWordsPerSentence <= 28) {
    status  = 'warning';
    message = `متوسط ${avgWordsPerSentence} كلمة/جملة — جمل طويلة نسبياً، حاول تقسيمها`;
  } else {
    status  = 'warning';
    message = `متوسط ${avgWordsPerSentence} كلمة/جملة — جمل طويلة جداً، يصعب قراءتها`;
  }

  return {
    readability: {
      status,
      avgWordsPerSentence,
      sentenceCount: sentCount,
      message,
    }
  };
}

// 28. DUPLICATE TITLE/H1 (exact match = weak content variety)
function checkDuplicateTitleH1(html) {
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const h1Match    = html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i);

  const title = titleMatch ? decode(stripTags(titleMatch[1])).trim() : '';
  const h1    = h1Match    ? decode(stripTags(h1Match[1])).trim()    : '';

  if (!title || !h1) return { duplicateTitleH1: { status: 'good', isDuplicate: false, message: 'لا يمكن المقارنة' } };

  const isDuplicate = title.toLowerCase() === h1.toLowerCase();
  return {
    duplicateTitleH1: {
      status: isDuplicate ? 'warning' : 'good',
      isDuplicate,
      message: isDuplicate
        ? 'Title وH1 متطابقان تماماً — يُفضّل تنويعهما لتغطية كلمات مفتاحية أوسع'
        : 'Title وH1 منوّعان ✓',
    }
  };
}

// 29. CONTENT POSITION IN HTML (how early does real content appear?)
function checkContentPosition(html) {
  const bodyMatch = html.match(/<body[^>]*>/i);
  if (!bodyMatch) return { contentPosition: { status: 'warning', message: 'تعذّر تحديد بداية body' } };

  const bodyStart = bodyMatch.index + bodyMatch[0].length;
  const afterBody = html.slice(bodyStart);

  // Find first meaningful text block (h1 or p with 20+ chars)
  const firstContentMatch = afterBody.match(/<(h1|p)[^>]*>([^<]{20,})/i);
  if (!firstContentMatch) {
    return { contentPosition: { status: 'warning', bytesBeforeContent: null, message: 'تعذّر تحديد موقع المحتوى الرئيسي' } };
  }

  const bytesBeforeContent = firstContentMatch.index;
  const pctOfPage = +((bytesBeforeContent / html.length) * 100).toFixed(1);

  return {
    contentPosition: {
      status : pctOfPage <= 25 ? 'good' : pctOfPage <= 50 ? 'warning' : 'error',
      bytesBeforeContent,
      percentOfPage: pctOfPage,
      message: pctOfPage <= 25
        ? `المحتوى الرئيسي يظهر مبكراً (${pctOfPage}% من الصفحة) ✓`
        : `المحتوى الرئيسي متأخر (${pctOfPage}% من الصفحة) — قد يكون مدفوناً خلف كود كثير`,
    }
  };
}

// 30. SECURITY HEADERS
function checkSecurityHeaders(response) {
  const hsts  = response.headers.get('strict-transport-security');
  const xcto  = response.headers.get('x-content-type-options');
  const xfo   = response.headers.get('x-frame-options');
  const csp   = response.headers.get('content-security-policy');
  const refpol= response.headers.get('referrer-policy');

  const present = [hsts, xcto, xfo, csp, refpol].filter(Boolean).length;
  const total   = 5;
  const missing = [
    !hsts   && 'Strict-Transport-Security',
    !xcto   && 'X-Content-Type-Options',
    !xfo    && 'X-Frame-Options',
    !csp    && 'Content-Security-Policy',
    !refpol && 'Referrer-Policy',
  ].filter(Boolean);

  return {
    securityHeaders: {
      status : present === total ? 'good' : present >= 3 ? 'warning' : 'error',
      present,
      total,
      hasHsts: !!hsts,
      hasCsp : !!csp,
      missing,
      message: present === total
        ? 'جميع رؤوس الأمان الأساسية موجودة ✓'
        : `${present}/${total} رؤوس أمان موجودة — مفقود: ${missing.join(', ')}`,
    }
  };
}

// 31. REDIRECT CHAIN
async function traceRedirectChain(startUrl, maxHops = 5) {
  const chain      = [];
  let   current    = startUrl;
  const overallDeadline = Date.now() + 5000; // 5s total budget — never block main analysis significantly

  for (let i = 0; i < maxHops; i++) {
    if (Date.now() > overallDeadline) break;

    try {
      const ctrl    = new AbortController();
      const timeout = setTimeout(() => ctrl.abort(), 2000); // 2s per hop max
      const r = await fetch(current, {
        method: 'HEAD',
        redirect: 'manual',
        signal: ctrl.signal,
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SEOCheckerBot/2.0)' },
      });
      clearTimeout(timeout);

      if (r.status >= 300 && r.status < 400) {
        const location = r.headers.get('location');
        if (!location) break;
        const next = new URL(location, current).href;
        chain.push({ from: current, to: next, status: r.status });
        if (next === current) break; // loop guard
        current = next;
      } else {
        break;
      }
    } catch {
      break;
    }
  }
  return chain;
}

function checkRedirectChain(chain) {
  const hops = chain.length;
  if (hops === 0) {
    return { redirectChain: { status: 'good', hops: 0, chain: [], message: 'لا توجد تحويلات — وصول مباشر ✓' } };
  }

  return {
    redirectChain: {
      status : hops === 1 ? 'good' : hops <= 2 ? 'warning' : 'error',
      hops,
      chain  : chain.map(c => ({ from: c.from, to: c.to, status: c.status })),
      message: hops === 1
        ? `تحويل واحد فقط (${chain[0].status}) — مقبول`
        : `${hops} تحويلات متتالية — يبطئ التحميل ويُضعف SEO، اجعله تحويلاً مباشراً`,
    }
  };
}

// 32. AMP
function checkAmp(html) {
  const isAmpPage = /<html[^>]+(?:amp|⚡)[\s>]/i.test(html.slice(0, 1000));
  const ampLink   = html.match(/<link[^>]+rel=["']amphtml["'][^>]+href=["']([^"']*)["']/i);

  return {
    amp: {
      status : 'good', // informational only — not having AMP isn't an error
      isAmpPage,
      hasAmpVersion: !!ampLink,
      ampUrl: ampLink ? ampLink[1] : null,
      message: isAmpPage
        ? 'هذه نسخة AMP من الصفحة'
        : ampLink
        ? `يوجد نسخة AMP بديلة: ${ampLink[1]}`
        : 'لا توجد نسخة AMP (اختياري حسب نوع الموقع)',
    }
  };
}

// 33. PWA / MANIFEST
function checkPwa(html) {
  const manifest   = html.match(/<link[^>]+rel=["']manifest["'][^>]+href=["']([^"']*)["']/i);
  const themeColor = /<meta[^>]+name=["']theme-color["']/i.test(html);
  const appleCapable = /<meta[^>]+name=["']apple-mobile-web-app-capable["']/i.test(html);

  const hasManifest = !!manifest;
  return {
    pwa: {
      status : hasManifest ? 'good' : 'warning',
      hasManifest,
      manifestUrl: manifest ? manifest[1] : null,
      hasThemeColor: themeColor,
      appleCapable,
      message: hasManifest
        ? `Web App Manifest موجود${themeColor ? ' + theme-color' : ''} — يدعم PWA`
        : 'لا يوجد manifest.json — الموقع لا يدعم خصائص PWA (تثبيت كتطبيق)',
    }
  };
}

// 34. MIXED CONTENT
function checkMixedContent(html, finalUrl) {
  if (!finalUrl.startsWith('https://')) {
    return { mixedContent: { status: 'good', count: 0, message: 'الصفحة ليست HTTPS — الفحص غير منطبق' } };
  }

  const httpResources = [
    ...html.matchAll(/\s(?:src|href)=["']http:\/\/(?!schema\.org)([^"']*)["']/gi),
  ];

  const count = httpResources.length;
  return {
    mixedContent: {
      status : count === 0 ? 'good' : count <= 2 ? 'warning' : 'error',
      count,
      examples: httpResources.slice(0, 3).map(m => 'http://' + m[1]),
      message: count === 0
        ? 'لا يوجد Mixed Content — جميع الموارد عبر HTTPS ✓'
        : `${count} مورد يُحمَّل عبر HTTP داخل صفحة HTTPS — قد يُحجب من المتصفح`,
    }
  };
}

// 35. HTTP PROTOCOL VERSION
function checkHttpProtocol(response) {
  // Cloudflare exposes this via cf-ray presence + alt-svc as a hint; we infer from headers
  const altSvc = response.headers.get('alt-svc') ?? '';
  const server = response.headers.get('server') ?? '';
  const supportsH3 = /h3/i.test(altSvc);
  const supportsH2 = /h2/i.test(altSvc) || server.toLowerCase().includes('cloudflare');

  return {
    httpProtocol: {
      status : supportsH3 || supportsH2 ? 'good' : 'warning',
      supportsH3,
      supportsH2,
      message: supportsH3
        ? 'الموقع يدعم HTTP/3 ✓'
        : supportsH2
        ? 'الموقع يدعم HTTP/2 ✓'
        : 'لم يتم اكتشاف HTTP/2 أو HTTP/3 بوضوح — تحقق يدوياً من إعدادات السيرفر',
    }
  };
}

// 36. COOKIE SECURITY
function checkCookieSecurity(response) {
  const setCookie = response.headers.get('set-cookie');
  if (!setCookie) {
    return { cookieSecurity: { status: 'good', count: 0, message: 'لا توجد كوكيز في الاستجابة الأولى' } };
  }

  const cookies = setCookie.split(/,(?=\s*\w+=)/); // naive split, good enough for single header
  let insecureCount = 0;
  for (const c of cookies) {
    const lower = c.toLowerCase();
    const hasSecure   = lower.includes('secure');
    const hasHttpOnly = lower.includes('httponly');
    const hasSameSite = lower.includes('samesite');
    if (!hasSecure || !hasHttpOnly || !hasSameSite) insecureCount++;
  }

  return {
    cookieSecurity: {
      status : insecureCount === 0 ? 'good' : 'warning',
      total: cookies.length,
      insecureCount,
      message: insecureCount === 0
        ? `جميع الكوكيز (${cookies.length}) تحتوي على Secure/HttpOnly/SameSite ✓`
        : `${insecureCount} من ${cookies.length} كوكيز تفتقر لإحدى علامات الأمان (Secure/HttpOnly/SameSite)`,
    }
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
  const base = `${targetUrl.protocol}//${targetUrl.host}`;

  // First check robots.txt for Sitemap directive
  let robotsSitemapUrl = null;
  try {
    const r = await fetch(`${base}/robots.txt`, { headers: { 'User-Agent': 'SEOCheckerBot/2.0' } });
    if (r.ok) {
      const txt = await r.text();
      const match = txt.match(/^Sitemap:\s*(.+)$/im);
      if (match) robotsSitemapUrl = match[1].trim();
    }
  } catch { /* ignore */ }

  // Candidates: from robots.txt first, then common paths
  const candidates = [
    ...(robotsSitemapUrl ? [robotsSitemapUrl] : []),
    `${base}/sitemap.xml`,
    `${base}/sitemap_index.xml`,
    `${base}/sitemap/sitemap.xml`,
  ];

  for (const candidate of candidates) {
    try {
      const r = await fetch(candidate, {
        headers: { 'User-Agent': 'SEOCheckerBot/2.0' },
        redirect: 'follow',
      });
      if (r.status === 200) {
        const text       = await r.text();
        const urlCount   = (text.match(/<url>/gi)    || []).length;
        const indexCount = (text.match(/<sitemap>/gi) || []).length;
        const isSitemapIndex = indexCount > 0 && urlCount === 0;
        return {
          sitemap: {
            status: 'good',
            exists: true,
            url: candidate,
            urlCount,
            indexCount,
            isSitemapIndex,
            fromRobots: candidate === robotsSitemapUrl,
            message: isSitemapIndex
              ? `Sitemap Index موجود — يحتوي على ${indexCount} sitemap`
              : `Sitemap موجود${urlCount > 0 ? ` — ${urlCount} رابط` : ''}`,
          }
        };
      }
    } catch { /* continue */ }
  }

  return { sitemap: { status: 'error', exists: false, message: 'Sitemap.xml غير موجود — أضفه لمساعدة Google على الفهرسة' } };
}


// ═══════════════════════════════════════════════
//  PROFESSIONAL SCORING SYSTEM — 8 CATEGORIES
// ═══════════════════════════════════════════════
function calcScore(checks) {

  // ── Category definitions ──
  const CATEGORIES = {
    technical: {
      label: 'Technical SEO',
      icon: '🔧',
      weight: 0.15,
      checks: {
        https:      { good: 15, warning: 4,  error: 0 },
        robotsTxt:  { good: 12, warning: 6,  error: 0 },
        sitemap:    { good: 15, warning: 0,  error: 0 },
        xRobotsTag: { good: 12, warning: 4,  error: 0 },
        charset:    { good: 12, warning: 6,  error: 0 },
        favicon:    { good: 10, warning: 5,  error: 0 },
        httpProtocol: { good: 12, warning: 6, error: 0 },
        redirectChain: { good: 12, warning: 6, error: 0 },
      }
    },
    onpage: {
      label: 'On-Page SEO',
      icon: '📝',
      weight: 0.18,
      checks: {
        title:              { good: 18, warning: 9,  error: 0 },
        metaDescription:    { good: 15, warning: 7,  error: 0 },
        h1:                 { good: 15, warning: 7,  error: 0 },
        wordCount:          { good: 12, warning: 6,  error: 0 },
        canonicalValidity:  { good: 14, warning: 6,  error: 0 },
        duplicateTitleH1:   { good: 10, warning: 5,  error: 0 },
        contentPosition:    { good: 16, warning: 8,  error: 0 },
      }
    },
    content: {
      label: 'Content Quality',
      icon: '🧠',
      weight: 0.13,
      checks: {
        keywordDensity: { good: 35, warning: 15, error: 0 },
        titleH1Match:   { good: 35, warning: 15, error: 0 },
        readability:    { good: 30, warning: 15, error: 0 },
      }
    },
    performance: {
      label: 'Performance',
      icon: '⚡',
      weight: 0.14,
      checks: {
        images:          { good: 25, warning: 12, error: 3 },
        renderBlocking:  { good: 30, warning: 12, error: 0 },
        textHtmlRatio:   { good: 20, warning: 10, error: 0 },
        resourceHints:   { good: 12, warning: 4,  error: 0 },
        mixedContent:    { good: 13, warning: 6,  error: 0 },
      }
    },
    mobile: {
      label: 'Mobile & UX',
      icon: '📱',
      weight: 0.10,
      checks: {
        viewport:         { good: 40, warning: 0,  error: 0 },
        imageDimensions:  { good: 35, warning: 17, error: 3 },
        pwa:              { good: 25, warning: 12, error: 0 },
      }
    },
    security: {
      label: 'Security',
      icon: '🔒',
      weight: 0.10,
      checks: {
        securityHeaders: { good: 60, warning: 30, error: 0 },
        cookieSecurity:  { good: 40, warning: 20, error: 0 },
      }
    },
    social: {
      label: 'Social SEO',
      icon: '🌐',
      weight: 0.08,
      checks: {
        openGraph    : { good: 50, warning: 25, error: 0 },
        twitterCards : { good: 30, warning: 15, error: 0 },
        lang         : { good: 20, warning: 10, error: 0 },
      }
    },
    structured: {
      label: 'Structured Data',
      icon: '🗂️',
      weight: 0.06,
      checks: {
        structuredDataTypes: { good: 100, warning: 40, error: 0 },
      }
    },
    links: {
      label: 'Links',
      icon: '🔗',
      weight: 0.04,
      checks: {
        links       : { good: 50, warning: 25, error: 0 },
        brokenLinks : { good: 50, warning: 20, error: 0 },
      }
    },
    international: {
      label: 'International',
      icon: '🌍',
      weight: 0.02,
      checks: {
        hreflang: { good: 100, warning: 60, error: 0 },
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

  // Keys to skip (they're sub-checks, informational only, or superseded by a deeper check)
  const SKIP = new Set([
    'headingsStructure', 'robotsMeta',
    'canonical',        // superseded by canonicalValidity (more detailed)
    'structuredData',   // superseded by structuredDataTypes (more detailed)
  ]);

  for (const [key, check] of Object.entries(checks)) {
    if (!check || check.status === 'good') continue;
    if (SKIP.has(key)) continue;

    // Special case: brokenLinks — only report if there are actually broken links
    if (key === 'brokenLinks') {
      if (check.broken?.length > 0) {
        issues.push({
          key,
          severity: check.status,
          message: check.message,
          value: check.broken.map(b => `${b.href} (${b.status === 0 ? 'Timeout' : 'HTTP ' + b.status})`).join('\n'),
        });
      }
      continue;
    }

    issues.push({
      key,
      severity: check.status,
      message: check.message,
      value: check.value ?? null,
    });
  }

  // Sort: errors first, then warnings; within same severity sort by key name
  issues.sort((a, b) => {
    if (a.severity !== b.severity) return a.severity === 'error' ? -1 : 1;
    return a.key.localeCompare(b.key);
  });

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
