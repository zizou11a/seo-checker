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
  const allowed = '*';

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

      // 5. Run analysis
      try {
        const result = await analyzeSite(targetUrl);
        return json(
          result,
          200,
          {
            ...cors,
            'X-RateLimit-Limit'    : String(CONFIG.RATE_LIMIT_REQUESTS),
            'X-RateLimit-Remaining': String(limit.remaining),
          }
        );
      } catch (err) {
        // أخطاء منظّمة من seoError()
        const status  = err.httpStatus ?? 502;
        const code    = err.code       ?? 'UNKNOWN';
        return json(
          { error: err.message, code, tip: getTip(code) },
          status,
          cors
        );
      }
    }

    // ── Route: / — health check ──
    return json({ status: 'ok', version: '1.2.0', message: 'SEO Checker API' }, 200, cors);
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
async function analyzeSite(targetUrl) {
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
  };

  // Fetch robots.txt & sitemap in parallel
  const [robotsResult, sitemapResult] = await Promise.allSettled([
    checkRobotsTxt(targetUrl),
    checkSitemap(targetUrl, html),
  ]);

  Object.assign(checks,
    robotsResult.status === 'fulfilled' ? robotsResult.value : { robotsTxt: { status: 'error', message: 'تعذّر الوصول' } },
    sitemapResult.status === 'fulfilled' ? sitemapResult.value : { sitemap: { status: 'error', message: 'تعذّر الوصول' } },
  );

  // ── Score ──
  const { score, breakdown } = calcScore(checks);

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
    checks,
    issues,
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
//  SCORING
// ═══════════════════════════════════════════════
function calcScore(checks) {
  const weights = {
    title:            { good: 15, warning: 8,  error: 0 },
    metaDescription:  { good: 12, warning: 6,  error: 0 },
    h1:               { good: 10, warning: 5,  error: 0 },
    https:            { good: 10, warning: 0,  error: 0 },
    viewport:         { good: 8,  warning: 0,  error: 0 },
    images:           { good: 8,  warning: 4,  error: 1 },
    canonical:        { good: 6,  warning: 3,  error: 0 },
    robotsTxt:        { good: 5,  warning: 2,  error: 0 },
    sitemap:          { good: 8,  warning: 0,  error: 0 },
    openGraph:        { good: 5,  warning: 2,  error: 0 },
    structuredData:   { good: 5,  warning: 2,  error: 0 },
    lang:             { good: 4,  warning: 2,  error: 0 },
    wordCount:        { good: 4,  warning: 2,  error: 0 },
  };

  let score = 0;
  const breakdown = {};

  for (const [key, w] of Object.entries(weights)) {
    const check = checks[key];
    if (!check) continue;
    const pts = w[check.status] ?? 0;
    score += pts;
    breakdown[key] = { status: check.status, points: pts, max: w.good };
  }

  return { score: Math.min(100, score), breakdown };
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
