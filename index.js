// index.js
// Keymo Proxy Server — production grade
//
// Features:
//   ✅ Dual provider: Anthropic + OpenAI (switch via env var, no app changes)
//   ✅ Three-window rate limiting: per-minute, per-hour, per-day
//   ✅ Rich error responses with exact reset times + upgrade message
//   ✅ Response caching — identical requests return instantly, zero API cost
//   ✅ Abuse protection — input length limits + prompt injection detection
//   ✅ Cost tracking — estimates token spend per request
//   ✅ Health + stats endpoint at /health
//   ✅ Keep-alive ping — prevents Railway cold starts
//
// Rate limits (free tier MVP):
//   15  rewrites / minute
//   100 rewrites / hour
//   500 rewrites / day

const express = require('express')
const fetch   = require('node-fetch')
const cors    = require('cors')
const crypto  = require('crypto')
const app     = express()

app.use(cors())
app.use(express.json({ limit: '10kb' })) // reject oversized payloads immediately

// ─── Configuration ────────────────────────────────────────────────────────────
// All values readable from environment variables so you can tune
// without touching code or rebuilding the app.

const CONFIG = {
    // Provider: 'anthropic' or 'openai'
    provider:        process.env.LLM_PROVIDER       || 'anthropic',

    // API Keys — set in Railway Variables tab, never hardcode here
    anthropicKey:    process.env.ANTHROPIC_API_KEY   || '',
    openaiKey:       process.env.OPENAI_API_KEY       || '',

    // Models
    anthropicModel:  process.env.ANTHROPIC_MODEL     || 'claude-haiku-4-5-20251001',
    openaiModel:     process.env.OPENAI_MODEL         || 'gpt-4o-mini',

    // Rate limits — free tier MVP
    minuteLimit:     parseInt(process.env.RATE_LIMIT_PER_MINUTE) || 15,
    hourLimit:       parseInt(process.env.RATE_LIMIT_PER_HOUR)   || 100,
    dayLimit:        parseInt(process.env.RATE_LIMIT_PER_DAY)    || 500,

    // Abuse protection
    maxInputLength:  parseInt(process.env.MAX_INPUT_LENGTH)      || 1000,
    maxSystemLength: parseInt(process.env.MAX_SYSTEM_LENGTH)     || 2000,

    // Cache
    cacheTTLMinutes: parseInt(process.env.CACHE_TTL_MINUTES)     || 60,
    maxCacheEntries: parseInt(process.env.MAX_CACHE_ENTRIES)      || 500,

    // Upgrade message shown when any limit is hit
    upgradeMessage:  process.env.UPGRADE_MESSAGE
                     || 'Get unlimited rewrites with Keymo Pro — coming soon.',

    port:            parseInt(process.env.PORT) || 3000
}

// ─── Stats ────────────────────────────────────────────────────────────────────

const stats = {
    totalRequests:   0,
    cacheHits:       0,
    rateLimitBlocks: 0,
    abuseBlocks:     0,
    errors:          0,
    estimatedTokens: 0,
    startTime:       Date.now()
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────
// Three independent sliding windows per IP.
// Each window tracks its own timestamps and resets independently.
// Per-minute checked first (abuse), then hour (heavy use), then day (cost cap).

const rateLimitStore = new Map()

const LIMITS = {
    minute: { max: CONFIG.minuteLimit, windowMs: 60 * 1000,           label: 'minute' },
    hour:   { max: CONFIG.hourLimit,   windowMs: 60 * 60 * 1000,      label: 'hour'   },
    day:    { max: CONFIG.dayLimit,    windowMs: 24 * 60 * 60 * 1000, label: 'day'    }
}

function formatTimeRemaining(ms) {
    const seconds = Math.ceil(ms / 1000)
    const minutes = Math.ceil(ms / 60000)
    const hours   = Math.ceil(ms / 3600000)

    if (seconds < 60)  return `${seconds} second${seconds === 1 ? '' : 's'}`
    if (minutes < 60)  return `${minutes} minute${minutes === 1 ? '' : 's'}`
    return `${hours} hour${hours === 1 ? '' : 's'}`
}

function checkRateLimit(ip) {
    const now   = Date.now()
    const entry = rateLimitStore.get(ip) || { minute: [], hour: [], day: [] }

    // Slide all three windows — remove expired timestamps
    entry.minute = entry.minute.filter(t => now - t < LIMITS.minute.windowMs)
    entry.hour   = entry.hour.filter(t =>   now - t < LIMITS.hour.windowMs)
    entry.day    = entry.day.filter(t =>    now - t < LIMITS.day.windowMs)

    // ── Per-minute check ──────────────────────────────────────────
    if (entry.minute.length >= LIMITS.minute.max) {
        const resetsAt    = entry.minute[0] + LIMITS.minute.windowMs
        const timeLeft    = resetsAt - now
        const timeStr     = formatTimeRemaining(timeLeft)
        return {
            limited:   true,
            window:    'minute',
            limit:     LIMITS.minute.max,
            resetsAt,
            message:   `Per-minute limit reached (${LIMITS.minute.max} rewrites/min). Resets in ${timeStr}.`
        }
    }

    // ── Per-hour check ────────────────────────────────────────────
    if (entry.hour.length >= LIMITS.hour.max) {
        const resetsAt    = entry.hour[0] + LIMITS.hour.windowMs
        const timeLeft    = resetsAt - now
        const timeStr     = formatTimeRemaining(timeLeft)
        return {
            limited:   true,
            window:    'hour',
            limit:     LIMITS.hour.max,
            resetsAt,
            message:   `Hourly limit reached (${LIMITS.hour.max} rewrites/hr). Resets in ${timeStr}.`
        }
    }

    // ── Per-day check ─────────────────────────────────────────────
    if (entry.day.length >= LIMITS.day.max) {
        const resetsAt    = entry.day[0] + LIMITS.day.windowMs
        const timeLeft    = resetsAt - now
        const timeStr     = formatTimeRemaining(timeLeft)
        return {
            limited:   true,
            window:    'day',
            limit:     LIMITS.day.max,
            resetsAt,
            message:   `Daily limit reached (${LIMITS.day.max} rewrites/day). Resets in ${timeStr}.`
        }
    }

    // ── All checks passed — record this request ───────────────────
    entry.minute.push(now)
    entry.hour.push(now)
    entry.day.push(now)
    rateLimitStore.set(ip, entry)

    return {
        limited:         false,
        minuteRemaining: LIMITS.minute.max - entry.minute.length,
        hourRemaining:   LIMITS.hour.max   - entry.hour.length,
        dayRemaining:    LIMITS.day.max    - entry.day.length
    }
}

// Clean up stale IP entries every hour to prevent memory growth
setInterval(() => {
    const now    = Date.now()
    const oneDay = 24 * 60 * 60 * 1000
    let   removed = 0
    for (const [ip, entry] of rateLimitStore.entries()) {
        const hasActivity = entry.day.some(t => now - t < oneDay)
        if (!hasActivity) {
            rateLimitStore.delete(ip)
            removed++
        }
    }
    if (removed > 0) {
        console.log(`[cleanup] Removed ${removed} stale IPs. Active: ${rateLimitStore.size}`)
    }
}, 60 * 60 * 1000)

// ─── Response Cache ───────────────────────────────────────────────────────────
// Caches responses by content hash (system prompt + user message + provider).
// Identical rewrites return instantly — no API call, no cost, no latency.

const responseCache = new Map()
const cacheOrder    = []

function getCacheKey(system, message, provider, temperature) {
    const t = temperature ?? 'default'
    return crypto
        .createHash('md5')
        .update(`${provider}:${t}:${system}:${message}`)
        .digest('hex')
}

function getFromCache(key) {
    const entry = responseCache.get(key)
    if (!entry) return null

    const ageMs  = Date.now() - entry.timestamp
    const maxAge = CONFIG.cacheTTLMinutes * 60 * 1000

    if (ageMs > maxAge) {
        responseCache.delete(key)
        return null
    }

    return entry.value
}

function setInCache(key, value) {
    // LRU eviction — remove oldest entry when at capacity
    if (responseCache.size >= CONFIG.maxCacheEntries) {
        const oldest = cacheOrder.shift()
        if (oldest) responseCache.delete(oldest)
    }
    responseCache.set(key, { value, timestamp: Date.now() })
    cacheOrder.push(key)
}

// ─── Abuse Protection ─────────────────────────────────────────────────────────
// Catches prompt injection attempts and misuse before they hit the API.

const ABUSE_PATTERNS = [
    /ignore (all |previous |above )?instructions/i,
    /forget (everything|your instructions|your prompt)/i,
    /you are now/i,
    /pretend (to be|you are|you're)/i,
    /jailbreak/i,
    /\bDAN\b/,
    /<script[\s\S]*?>/i,
    /system\s*:/i
]

function checkForAbuse(input) {
    if (input.length > CONFIG.maxInputLength) {
        return {
            abusive: true,
            reason:  `Input too long (${input.length} chars, max ${CONFIG.maxInputLength})`
        }
    }
    for (const pattern of ABUSE_PATTERNS) {
        if (pattern.test(input)) {
            return { abusive: true, reason: 'Input contains disallowed content' }
        }
    }
    return { abusive: false }
}

// ─── Token Estimator ──────────────────────────────────────────────────────────
// Rough estimate at ~4 chars per token. Good enough for cost monitoring.

function estimateTokens(text) {
    return Math.ceil((text || '').length / 4)
}

// ─── Anthropic Streaming ──────────────────────────────────────────────────────

async function streamAnthropic(system, messages, res, opts = {}) {
    const body = {
        model:      CONFIG.anthropicModel,
        max_tokens: opts.max_tokens     ?? 1024,
        stream:     true,
        system,
        messages
    }
    if (opts.temperature    !== undefined) body.temperature    = opts.temperature
    if (opts.stop_sequences?.length)       body.stop_sequences = opts.stop_sequences

    const response = await fetch('https://api.anthropic.com/v1/messages', {
        method:  'POST',
        headers: {
            'Content-Type':      'application/json',
            'x-api-key':         CONFIG.anthropicKey,
            'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify(body)
    })

    if (!response.ok) {
        const err = await response.text()
        throw new Error(`Anthropic ${response.status}: ${err}`)
    }

    // Pipe stream to client AND collect full text for caching simultaneously
    return new Promise((resolve, reject) => {
        let fullText = ''

        response.body.on('data', chunk => {
            // Forward raw SSE chunk to the app
            res.write(chunk)

            // Parse tokens to build full text for cache
            const lines = chunk.toString().split('\n')
            for (const line of lines) {
                if (!line.startsWith('data: ')) continue
                const data = line.slice(6)
                if (data === '[DONE]') continue
                try {
                    const json = JSON.parse(data)
                    if (json.type === 'content_block_delta' && json.delta?.text) {
                        fullText += json.delta.text
                    }
                } catch {}
            }
        })

        response.body.on('end',   () => resolve(fullText))
        response.body.on('error', reject)
    })
}

// ─── OpenAI Streaming ─────────────────────────────────────────────────────────

async function streamOpenAI(system, messages, res, opts = {}) {
    const body = {
        model:      CONFIG.openaiModel,
        max_tokens: opts.max_tokens     ?? 1024,
        stream:     true,
        messages:   [{ role: 'system', content: system }, ...messages]
    }
    if (opts.temperature !== undefined) body.temperature = opts.temperature
    if (opts.stop_sequences?.length)    body.stop        = opts.stop_sequences

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method:  'POST',
        headers: {
            'Content-Type':  'application/json',
            'Authorization': `Bearer ${CONFIG.openaiKey}`
        },
        body: JSON.stringify(body)
    })

    if (!response.ok) {
        const err = await response.text()
        throw new Error(`OpenAI ${response.status}: ${err}`)
    }

    return new Promise((resolve, reject) => {
        let fullText = ''

        response.body.on('data', chunk => {
            res.write(chunk)

            const lines = chunk.toString().split('\n')
            for (const line of lines) {
                if (!line.startsWith('data: ')) continue
                const data = line.slice(6)
                if (data === '[DONE]') continue
                try {
                    const json  = JSON.parse(data)
                    const token = json.choices?.[0]?.delta?.content
                    if (token) fullText += token
                } catch {}
            }
        })

        response.body.on('end',   () => resolve(fullText))
        response.body.on('error', reject)
    })
}

// ─── /rewrite ─────────────────────────────────────────────────────────────────

app.post('/rewrite', async (req, res) => {
    stats.totalRequests++

    // Get real IP (Railway sits behind a proxy)
    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim()
               || req.socket.remoteAddress
               || 'unknown'

    const {
    messages,
    system,
    provider:      requestedProvider,
    temperature,
    max_tokens,
    stop_sequences,
    isRetry
} = req.body

    // ── Validate request body ────────────────────────────────────
    if (!messages || !Array.isArray(messages) || !system) {
        return res.status(400).json({ error: 'Invalid request body' })
    }

    const userMessage = messages.find(m => m.role === 'user')?.content || ''

    // ── Abuse check ──────────────────────────────────────────────
    const abuseCheck = checkForAbuse(userMessage)
    if (abuseCheck.abusive) {
        stats.abuseBlocks++
        console.warn(`[abuse] ${ip}: ${abuseCheck.reason}`)
        return res.status(400).json({ error: 'Invalid input' })
    }

    if (system.length > CONFIG.maxSystemLength) {
        stats.abuseBlocks++
        return res.status(400).json({ error: 'Invalid request' })
    }

    // ── Rate limit check ─────────────────────────────────────────
    const rateCheck = checkRateLimit(ip)
    if (rateCheck.limited) {
        stats.rateLimitBlocks++
        console.warn(`[rate-limit] ${ip} | ${rateCheck.window}: ${rateCheck.message}`)

        return res.status(429).json({
            error:   'rate_limited',
            window:  rateCheck.window,           // 'minute' | 'hour' | 'day'
            message: rateCheck.message,          // human-readable limit message
            resetsAt: rateCheck.resetsAt,        // Unix ms timestamp — app formats this
            limit:   rateCheck.limit,            // the max for this window
            upgrade: CONFIG.upgradeMessage       // upgrade nudge
        })
    }

    // ── Cache check ──────────────────────────────────────────────
    const provider = requestedProvider || CONFIG.provider
    const cacheKey = getCacheKey(system, userMessage, provider, temperature)
    const cached   = !isRetry ? getFromCache(cacheKey) : null

    if (cached) {
        stats.cacheHits++
        console.log(`[cache-hit] ${ip}`)
        // Return as SSE so app streaming code works unchanged
        res.setHeader('Content-Type', 'text/event-stream')
        res.setHeader('Cache-Control', 'no-cache')
        res.setHeader('X-Cache', 'HIT')
        res.write(`data: ${JSON.stringify({
            type:  'content_block_delta',
            delta: { type: 'text_delta', text: cached }
        })}\n\n`)
        res.write('data: [DONE]\n\n')
        return res.end()
    }

    // ── Log + set headers ────────────────────────────────────────
    const inputTokens = estimateTokens(system + userMessage)
    stats.estimatedTokens += inputTokens
    console.log(`[request] ${ip} | ${provider} | ~${inputTokens} tokens | min:${rateCheck.minuteRemaining} hr:${rateCheck.hourRemaining} day:${rateCheck.dayRemaining}`)

    res.setHeader('Content-Type',       'text/event-stream')
    res.setHeader('Cache-Control',      'no-cache')
    res.setHeader('X-Cache',            'MISS')
    res.setHeader('X-Minute-Remaining', rateCheck.minuteRemaining)
    res.setHeader('X-Hour-Remaining',   rateCheck.hourRemaining)
    res.setHeader('X-Day-Remaining',    rateCheck.dayRemaining)

    // ── Stream from provider ─────────────────────────────────────
    try {
        let fullText = ''

        const opts = { temperature, max_tokens, stop_sequences }

        if (provider === 'openai') {
            fullText = await streamOpenAI(system, messages, res, opts)
        } else {
            fullText = await streamAnthropic(system, messages, res, opts)
        }

        // Cache completed response
        if (fullText.trim() && !isRetry) {
            setInCache(cacheKey, fullText)
            const outputTokens = estimateTokens(fullText)
            stats.estimatedTokens += outputTokens
            console.log(`[complete] ${ip} | ~${outputTokens} output tokens | cache: ${responseCache.size} entries`)
        }

        res.end()

    } catch (error) {
        stats.errors++
        console.error(`[error] ${ip}: ${error.message}`)
        if (!res.headersSent) {
            res.status(500).json({ error: 'AI provider error. Please try again.' })
        } else {
            res.end()
        }
    }
})

// ─── /health ──────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
    const uptimeHours = ((Date.now() - stats.startTime) / 3600000).toFixed(1)

    // Cost estimate: Haiku ~$0.25/M input + $1.25/M output, avg ~$0.75/M
    const estimatedCost = ((stats.estimatedTokens / 1_000_000) * 0.75).toFixed(4)

    res.json({
        status:   'ok',
        service:  'keymo-proxy',
        provider: CONFIG.provider,
        model:    CONFIG.provider === 'anthropic' ? CONFIG.anthropicModel : CONFIG.openaiModel,
        uptime:   `${uptimeHours}h`,
        limits: {
            perMinute: CONFIG.minuteLimit,
            perHour:   CONFIG.hourLimit,
            perDay:    CONFIG.dayLimit
        },
        stats: {
            totalRequests:   stats.totalRequests,
            cacheHits:       stats.cacheHits,
            cacheHitRate:    stats.totalRequests > 0
                             ? `${((stats.cacheHits / stats.totalRequests) * 100).toFixed(1)}%`
                             : '0%',
            rateLimitBlocks: stats.rateLimitBlocks,
            abuseBlocks:     stats.abuseBlocks,
            errors:          stats.errors,
            estimatedTokens: stats.estimatedTokens,
            estimatedCostUSD: `$${estimatedCost}`
        },
        cache: {
            entries:    responseCache.size,
            maxEntries: CONFIG.maxCacheEntries,
            ttlMinutes: CONFIG.cacheTTLMinutes
        },
        activeIPs: rateLimitStore.size
    })
})

// ─── Keep-alive ───────────────────────────────────────────────────────────────
// Pings every 25 minutes so Railway free tier never cold-starts

setInterval(() => {
    fetch(`http://localhost:${CONFIG.port}/health`)
        .then(() => console.log('[keep-alive] ok'))
        .catch(err => console.error('[keep-alive] failed:', err.message))
}, 25 * 60 * 1000)

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(CONFIG.port, () => {
    console.log(`
╔══════════════════════════════════════════╗
║          Keymo Proxy Server              ║
╠══════════════════════════════════════════╣
║  Port:       ${String(CONFIG.port).padEnd(28)}║
║  Provider:   ${CONFIG.provider.padEnd(28)}║
║  Limits:     ${CONFIG.minuteLimit}/min, ${CONFIG.hourLimit}/hr, ${CONFIG.dayLimit}/day${' '.repeat(Math.max(0, 14 - String(CONFIG.minuteLimit).length - String(CONFIG.hourLimit).length - String(CONFIG.dayLimit).length))}║
║  Cache:      ${CONFIG.cacheTTLMinutes}min TTL, ${CONFIG.maxCacheEntries} max entries${' '.repeat(Math.max(0, 15 - String(CONFIG.cacheTTLMinutes).length - String(CONFIG.maxCacheEntries).length))}║
╚══════════════════════════════════════════╝
    `)

    if (CONFIG.provider === 'anthropic' && !CONFIG.anthropicKey) {
        console.error('⚠️  ANTHROPIC_API_KEY is not set — requests will fail')
    }
    if (CONFIG.provider === 'openai' && !CONFIG.openaiKey) {
        console.error('⚠️  OPENAI_API_KEY is not set — requests will fail')
    }
})
