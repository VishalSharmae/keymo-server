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
const fetch = require('node-fetch')
const cors = require('cors')
const crypto = require('crypto')
const app = express()
const fs = require('fs')
const PAID_USERS_FILE = process.env.PAID_USERS_FILE || '/data/keymo-paid-users.json'
fs.mkdirSync(require('path').dirname(PAID_USERS_FILE), {
    recursive: true
})

app.use(cors())
app.use(express.json({
    limit: '10kb'
})) // reject oversized payloads immediately

// ─── Configuration ────────────────────────────────────────────────────────────
// All values readable from environment variables so you can tune
// without touching code or rebuilding the app.

const CONFIG = {
    // Provider: 'anthropic' or 'openai'
    provider: process.env.LLM_PROVIDER || 'anthropic',

    // API Keys — set in Railway Variables tab, never hardcode here
    anthropicKey: process.env.ANTHROPIC_API_KEY || '',
    openaiKey: process.env.OPENAI_API_KEY || '',

    // Models
    anthropicModel: process.env.ANTHROPIC_MODEL || 'claude-haiku-4-5-20251001',
    openaiModel: process.env.OPENAI_MODEL || 'gpt-4o-mini',

    // Rate limits — free tier MVP
    minuteLimit: parseInt(process.env.RATE_LIMIT_PER_MINUTE) || 15,
    hourLimit: parseInt(process.env.RATE_LIMIT_PER_HOUR) || 100,
    dayLimit: parseInt(process.env.RATE_LIMIT_PER_DAY) || 500,

    // Abuse protection
    maxInputLength: parseInt(process.env.MAX_INPUT_LENGTH) || 1000,
    maxSystemLength: parseInt(process.env.MAX_SYSTEM_LENGTH) || 2000,

    // Cache
    cacheTTLMinutes: parseInt(process.env.CACHE_TTL_MINUTES) || 60,
    maxCacheEntries: parseInt(process.env.MAX_CACHE_ENTRIES) || 500,

    // Upgrade message shown when any limit is hit
    upgradeMessage: process.env.UPGRADE_MESSAGE ||
        'Get unlimited rewrites with Keymo Pro — $5/month.',

    maxInputFree: parseInt(process.env.MAX_INPUT_FREE) || 1000,
    maxInputPro: parseInt(process.env.MAX_INPUT_PRO) || 10000,

    port: parseInt(process.env.PORT) || 3000
}

// ─── Stats ────────────────────────────────────────────────────────────────────

const stats = {
    totalRequests: 0,
    cacheHits: 0,
    rateLimitBlocks: 0,
    abuseBlocks: 0,
    errors: 0,
    estimatedTokens: 0,
    startTime: Date.now()
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────
// Three independent sliding windows per IP.
// Each window tracks its own timestamps and resets independently.
// Per-minute checked first (abuse), then hour (heavy use), then day (cost cap).

const rateLimitStore = new Map()

const LIMITS = {
    minute: {
        max: CONFIG.minuteLimit,
        windowMs: 60 * 1000,
        label: 'minute'
    },
    hour: {
        max: CONFIG.hourLimit,
        windowMs: 60 * 60 * 1000,
        label: 'hour'
    },
    day: {
        max: CONFIG.dayLimit,
        windowMs: 24 * 60 * 60 * 1000,
        label: 'day'
    }
}

let paidUsers = new Map() // uid → expiry timestamp (ms)

function savePaidUsers() {
    const data = Object.fromEntries(paidUsers)
    fs.writeFileSync(PAID_USERS_FILE, JSON.stringify(data))
}

function loadPaidUsers() {
    try {
        if (fs.existsSync(PAID_USERS_FILE)) {
            const data = JSON.parse(fs.readFileSync(PAID_USERS_FILE, 'utf8'))
            paidUsers = new Map(Object.entries(data))
            console.log(`[startup] Loaded ${paidUsers.size} paid users`)
        }
    } catch (e) {
        console.error('[startup] Could not load paid users:', e.message)
    }
}

loadPaidUsers()

// Check if user is currently pro
function isUserPro(uid) {
    if (!uid || !paidUsers.has(uid)) return false
    const expiresAt = paidUsers.get(uid)
    return Date.now() < expiresAt // still valid if expiry is in the future
}

function formatTimeRemaining(ms) {
    const seconds = Math.ceil(ms / 1000)
    const minutes = Math.ceil(ms / 60000)
    const hours = Math.ceil(ms / 3600000)

    if (seconds < 60) return `${seconds} second${seconds === 1 ? '' : 's'}`
    if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'}`
    return `${hours} hour${hours === 1 ? '' : 's'}`
}

function checkRateLimit(ip) {
    const now = Date.now()
    const entry = rateLimitStore.get(ip) || {
        minute: [],
        hour: [],
        day: []
    }

    // Slide all three windows — remove expired timestamps
    entry.minute = entry.minute.filter(t => now - t < LIMITS.minute.windowMs)
    entry.hour = entry.hour.filter(t => now - t < LIMITS.hour.windowMs)
    entry.day = entry.day.filter(t => now - t < LIMITS.day.windowMs)

    // ── Per-minute check ──────────────────────────────────────────
    if (entry.minute.length >= LIMITS.minute.max) {
        const resetsAt = entry.minute[0] + LIMITS.minute.windowMs
        const timeLeft = resetsAt - now
        const timeStr = formatTimeRemaining(timeLeft)
        return {
            limited: true,
            window: 'minute',
            limit: LIMITS.minute.max,
            resetsAt,
            message: `Per-minute limit reached (${LIMITS.minute.max} rewrites/min). Resets in ${timeStr}.`
        }
    }

    // ── Per-hour check ────────────────────────────────────────────
    if (entry.hour.length >= LIMITS.hour.max) {
        const resetsAt = entry.hour[0] + LIMITS.hour.windowMs
        const timeLeft = resetsAt - now
        const timeStr = formatTimeRemaining(timeLeft)
        return {
            limited: true,
            window: 'hour',
            limit: LIMITS.hour.max,
            resetsAt,
            message: `Hourly limit reached (${LIMITS.hour.max} rewrites/hr). Resets in ${timeStr}.`
        }
    }

    // ── Per-day check ─────────────────────────────────────────────
    if (entry.day.length >= LIMITS.day.max) {
        const resetsAt = entry.day[0] + LIMITS.day.windowMs
        const timeLeft = resetsAt - now
        const timeStr = formatTimeRemaining(timeLeft)
        return {
            limited: true,
            window: 'day',
            limit: LIMITS.day.max,
            resetsAt,
            message: `Daily limit reached (${LIMITS.day.max} rewrites/day). Resets in ${timeStr}.`
        }
    }

    // ── All checks passed — record this request ───────────────────
    entry.minute.push(now)
    entry.hour.push(now)
    entry.day.push(now)
    rateLimitStore.set(ip, entry)

    return {
        limited: false,
        minuteRemaining: LIMITS.minute.max - entry.minute.length,
        hourRemaining: LIMITS.hour.max - entry.hour.length,
        dayRemaining: LIMITS.day.max - entry.day.length
    }
}

// Clean up stale IP entries every hour to prevent memory growth
setInterval(() => {
    const now = Date.now()
    const oneDay = 24 * 60 * 60 * 1000
    let removed = 0
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
const cacheOrder = []

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

    const ageMs = Date.now() - entry.timestamp
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
    responseCache.set(key, {
        value,
        timestamp: Date.now()
    })
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
]

function checkForAbuse(input) {
    if (input.length > CONFIG.maxInputLength) {
        return {
            abusive: true,
            reason: `Input too long (${input.length} chars, max ${CONFIG.maxInputLength})`
        }
    }
    for (const pattern of ABUSE_PATTERNS) {
        if (pattern.test(input)) {
            return {
                abusive: true,
                reason: 'Input contains disallowed content'
            }
        }
    }
    return {
        abusive: false
    }
}

// ─── Token Estimator ──────────────────────────────────────────────────────────
// Rough estimate at ~4 chars per token. Good enough for cost monitoring.

function estimateTokens(text) {
    return Math.ceil((text || '').length / 4)
}

// ─── Analytics ────────────────────────────────────────────────────────────────
// All events written to a daily JSONL file on persistent volume.
// Async + buffered so the request path is never blocked.

const ANALYTICS_DIR = process.env.ANALYTICS_DIR || '/data/analytics'
fs.mkdirSync(ANALYTICS_DIR, {
    recursive: true
})

let eventBuffer = []
const FLUSH_INTERVAL_MS = 5000 // flush every 5s
const FLUSH_MAX_EVENTS = 50 // or when buffer hits 50 events

function flushEvents() {
    if (eventBuffer.length === 0) return
    const today = new Date().toISOString().split('T')[0]
    const file = `${ANALYTICS_DIR}/usage-${today}.jsonl`
    const lines = eventBuffer.map(e => JSON.stringify(e)).join('\n') + '\n'
    eventBuffer = []
    fs.appendFile(file, lines, err => {
        if (err) console.error('[analytics] flush failed:', err.message)
    })
}

setInterval(flushEvents, FLUSH_INTERVAL_MS)
process.on('SIGTERM', flushEvents) // flush before Railway redeploys

function logEvent(event) {
    eventBuffer.push({
        ts: Date.now(),
        day: new Date().toISOString().split('T')[0],
        ...event
    })
    if (eventBuffer.length >= FLUSH_MAX_EVENTS) flushEvents()
}

// ─── Anthropic Streaming ──────────────────────────────────────────────────────

async function streamAnthropic(system, messages, res, opts = {}) {
    const body = {
        model: CONFIG.anthropicModel,
        max_tokens: opts.max_tokens ?? 1024,
        stream: true,
        system,
        messages
    }
    if (opts.temperature !== undefined) body.temperature = opts.temperature
    if (opts.stop_sequences?.length) body.stop_sequences = opts.stop_sequences

    const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-api-key': CONFIG.anthropicKey,
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

        response.body.on('end', () => resolve(fullText))
        response.body.on('error', reject)
    })
}

// ─── OpenAI Streaming ─────────────────────────────────────────────────────────

async function streamOpenAI(system, messages, res, opts = {}) {
    const body = {
        model: CONFIG.openaiModel,
        max_tokens: opts.max_tokens ?? 1024,
        stream: true,
        messages: [{
            role: 'system',
            content: system
        }, ...messages]
    }
    if (opts.temperature !== undefined) body.temperature = opts.temperature
    if (opts.stop_sequences?.length) body.stop = opts.stop_sequences

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
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
                    const json = JSON.parse(data)
                    const token = json.choices?.[0]?.delta?.content
                    if (token) fullText += token
                } catch {}
            }
        })

        response.body.on('end', () => resolve(fullText))
        response.body.on('error', reject)
    })
}

// ─── /rewrite ─────────────────────────────────────────────────────────────────

app.post('/rewrite', async (req, res) => {
    stats.totalRequests++

    // Get real IP (Railway sits behind a proxy)
    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() ||
        req.socket.remoteAddress || 'unknown'

    const {
        messages,
        system,
        provider: requestedProvider,
        temperature,
        max_tokens,
        stop_sequences,
        isRetry,
        uid,
        mode = 'unknown', // ← capture from app
        context = 'unknown' // ← capture from app
    } = req.body

    // ── Validate request body ────────────────────────────────────
    if (!messages || !Array.isArray(messages) || !system) {
        return res.status(400).json({
            error: 'Invalid request body'
        })
    }

    const userMessage = messages.find(m => m.role === 'user')?.content || ''
    const userId = uid || null
    const isPro = isUserPro(userId)

    // ── Abuse check ──────────────────────────────────────────────
    const abuseCheck = checkForAbuse(userMessage)
    if (abuseCheck.abusive) {
        stats.abuseBlocks++
        console.warn(`[abuse] ${ip}: ${abuseCheck.reason}`)
        return res.status(400).json({
            error: 'Invalid input'
        })
    }

    if (system.length > CONFIG.maxSystemLength) {
        stats.abuseBlocks++
        return res.status(400).json({
            error: 'Invalid request'
        })
    }
    const identifier = userId ? `uid:${userId}` : `ip:${ip}`
    const maxInput = isPro ? CONFIG.maxInputPro : CONFIG.maxInputFree

    // ── Rate limit check ─────────────────────────────────────────
    let rateCheck = {
        limited: false,
        minuteRemaining: '∞',
        hourRemaining: '∞',
        dayRemaining: '∞'
    }

    if (!isPro) {
        rateCheck = checkRateLimit(identifier)
        if (rateCheck.limited) {
            stats.rateLimitBlocks++
            logEvent({
                type: 'rate_limited',
                uid,
                mode,
                context,
                window: rateCheck.window,
                isPro
            })
            return res.status(429).json({
                error: 'rate_limited',
                window: rateCheck.window, // 'minute' | 'hour' | 'day'
                message: rateCheck.message, // human-readable limit message
                resetsAt: rateCheck.resetsAt, // Unix ms timestamp — app formats this
                limit: rateCheck.limit, // the max for this window
                upgrade: CONFIG.upgradeMessage // upgrade nudge
            })
        }
    }
    const maxProInput = CONFIG.maxInputPro

    // ── Message limit check ─────────────────────────────────────────
    if (userMessage.length > maxInput) {
        return res.status(400).json({
            error: 'input_too_long',
            message: `Your input is ${userMessage.length} characters. ${
            isPro
                ? `Keymo Pro supports up to ${maxProInput} characters.`
                : `Free tier supports up to ${maxInput} characters.`
        }`,
            upgrade: isPro ?
                undefined :
                `Upgrade to Keymo Pro — $5/month for up to ${maxProInput} characters.`
        })
    }

    // ── Cache check ──────────────────────────────────────────────
    const provider = requestedProvider || CONFIG.provider
    const cacheKey = getCacheKey(system, userMessage, provider, temperature)
    const cached = !isRetry ? getFromCache(cacheKey) : null

    if (cached) {
        stats.cacheHits++
        logEvent({
            type: 'rewrite',
            uid,
            mode,
            context,
            cached: true,
            isRetry: !!isRetry,
            isPro,
            provider: requestedProvider || CONFIG.provider,
            latencyMs: Date.now() - startedAt,
            inputChars: userMessage.length,
            outputChars: cached.length
        })
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

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('X-Cache', 'MISS')

    if (!isPro) {
        res.setHeader('X-Minute-Remaining', rateCheck.minuteRemaining)
        res.setHeader('X-Hour-Remaining', rateCheck.hourRemaining)
        res.setHeader('X-Day-Remaining', rateCheck.dayRemaining)
    } else {
        res.setHeader('X-Plan', 'pro')
    }

    // ── Stream from provider ─────────────────────────────────────
    try {
        let fullText = ''

        const opts = {
            temperature,
            max_tokens,
            stop_sequences
        }

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

        logEvent({
            type: 'rewrite',
            uid,
            mode,
            context,
            cached: false,
            isRetry: !!isRetry,
            isPro,
            provider,
            latencyMs: Date.now() - startedAt,
            inputChars: userMessage.length,
            outputChars: fullText.length,
            inputTokens,
            outputTokens: estimateTokens(fullText)
        })
        res.end()

    } catch (error) {
        stats.errors++
        console.error(`[error] ${ip}: ${error.message}`)
        logEvent({
            type: 'error',
            uid,
            mode,
            context,
            isPro,
            provider: requestedProvider || CONFIG.provider,
            message: error.message?.slice(0, 200)
        })
        if (!res.headersSent) {
            res.status(500).json({
                error: 'AI provider error. Please try again.'
            })
        } else {
            res.end()
        }
    }
})

// ─── /stats ───────────────────────────────────────────────────────────────────
// Auth via header, not URL (URLs leak into logs).
// Query params:
//   ?days=7   how many days of history (default 1, max 30)

app.get('/stats', (req, res) => {
    if (req.headers['x-admin-password'] !== process.env.STATS_PASSWORD) {
        return res.status(403).json({
            error: 'forbidden'
        })
    }

    flushEvents() // make sure latest events are on disk

    const days = Math.min(parseInt(req.query.days) || 1, 30)
    const events = []

    for (let i = 0; i < days; i++) {
        const d = new Date(Date.now() - i * 86400000).toISOString().split('T')[0]
        const file = `${ANALYTICS_DIR}/usage-${d}.jsonl`
        if (!fs.existsSync(file)) continue
        const lines = fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean)
        for (const l of lines) {
            try {
                events.push(JSON.parse(l))
            } catch {}
        }
    }

    const rewrites = events.filter(e => e.type === 'rewrite')
    const errors = events.filter(e => e.type === 'error')
    const limited = events.filter(e => e.type === 'rate_limited')
    const cached = rewrites.filter(e => e.cached)
    const retried = rewrites.filter(e => e.isRetry)

    const tally = (arr, key) => arr.reduce((acc, e) => {
        const k = e[key] || 'unknown'
        acc[k] = (acc[k] || 0) + 1
        return acc
    }, {})

    const uniqueUsers = new Set(rewrites.map(e => e.uid).filter(Boolean)).size
    const dau = {}
    for (const e of rewrites) {
        dau[e.day] = dau[e.day] || new Set()
        if (e.uid) dau[e.day].add(e.uid)
    }
    const dauSeries = Object.fromEntries(
        Object.entries(dau).map(([d, s]) => [d, s.size])
    )

    const latencies = rewrites
        .filter(e => !e.cached && typeof e.latencyMs === 'number')
        .map(e => e.latencyMs)
        .sort((a, b) => a - b)
    const p50 = latencies[Math.floor(latencies.length * 0.5)] || 0
    const p95 = latencies[Math.floor(latencies.length * 0.95)] || 0

    const totalInputTokens = rewrites.reduce((s, e) => s + (e.inputTokens || 0), 0)
    const totalOutputTokens = rewrites.reduce((s, e) => s + (e.outputTokens || 0), 0)
    // Haiku: $0.25/M input + $1.25/M output
    const costUSD = (totalInputTokens * 0.25 + totalOutputTokens * 1.25) / 1_000_000

    res.json({
        windowDays: days,
        totals: {
            rewrites: rewrites.length,
            errors: errors.length,
            rateLimited: limited.length,
            cacheHits: cached.length,
            retries: retried.length,
            cacheHitRate: rewrites.length ?
                `${(cached.length / rewrites.length * 100).toFixed(1)}%` : '0%',
            retryRate: rewrites.length ?
                `${(retried.length / rewrites.length * 100).toFixed(1)}%` : '0%',
            errorRate: events.length ?
                `${(errors.length / events.length * 100).toFixed(2)}%` : '0%'
        },
        users: {
            uniqueUsers,
            proUsers: paidUsers.size,
            dailyActive: dauSeries,
            avgRewritesPerUser: uniqueUsers ?
                (rewrites.length / uniqueUsers).toFixed(1) : '0'
        },
        latencyMs: {
            p50,
            p95
        },
        breakdown: {
            byMode: tally(rewrites, 'mode'),
            byContext: tally(rewrites, 'context'),
            byProvider: tally(rewrites, 'provider'),
            rateLimitsByWindow: tally(limited, 'window')
        },
        cost: {
            inputTokens: totalInputTokens,
            outputTokens: totalOutputTokens,
            estimatedUSD: `$${costUSD.toFixed(4)}`
        }
    })
})

//---- /dashboard -------------------------------------------------------------------------------------------------------------------------------

app.get('/dashboard', (req, res) => {
    res.type('html').send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Keymo Analytics</title>
<style>
    body { font: 14px -apple-system, sans-serif; max-width: 1100px; margin: 30px auto;
           padding: 0 20px; background: #0e0e10; color: #e8e8ea; }
    h1 { font-weight: 600; }
    h2 { font-weight: 500; color: #f6e0a3; margin-top: 28px; border-bottom: 1px solid #333; padding-bottom: 6px; }
    input { background: #1a1a1d; border: 1px solid #333; color: #fff; padding: 6px 10px; border-radius: 6px; }
    button { background: #f6e0a3; color: #000; border: 0; padding: 7px 14px; border-radius: 6px; cursor: pointer; font-weight: 600; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 14px 0; }
    .card { background: #16161a; padding: 14px; border-radius: 10px; border: 1px solid #26262b; }
    .card .v { font-size: 22px; font-weight: 600; }
    .card .l { font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 0.5px; }
    table { width: 100%; border-collapse: collapse; margin: 8px 0; }
    th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #26262b; }
    th { color: #888; font-weight: 500; font-size: 12px; }
    pre { background: #16161a; padding: 12px; border-radius: 8px; overflow: auto; font-size: 12px; }
</style>
</head>
<body>
<h1>📊 Keymo Analytics</h1>

<div>
    <input id="pw" type="password" placeholder="Admin password">
    <input id="days" type="number" value="7" min="1" max="30" style="width:60px">
    <button onclick="load()">Load</button>
</div>

<div id="out" style="margin-top:20px;color:#888">Enter password and click Load.</div>

<script>
async function load() {
    const pw   = document.getElementById('pw').value
    const days = document.getElementById('days').value
    const out  = document.getElementById('out')
    out.textContent = 'Loading…'

    const r = await fetch('/stats?days=' + days, {
        headers: { 'x-admin-password': pw }
    })
    if (!r.ok) { out.textContent = 'Auth failed'; return }
    const d = await r.json()

    const card = (l, v) => \`<div class="card"><div class="l">\${l}</div><div class="v">\${v}</div></div>\`
    const tbl  = (obj) => {
        const rows = Object.entries(obj).sort((a,b) => b[1]-a[1])
            .map(([k,v]) => \`<tr><td>\${k}</td><td>\${v}</td></tr>\`).join('')
        return \`<table><tr><th>Key</th><th>Count</th></tr>\${rows}</table>\`
    }

    out.innerHTML = \`
        <h2>Overview (\${d.windowDays}-day window)</h2>
        <div class="grid">
            \${card('Rewrites',      d.totals.rewrites)}
            \${card('Unique users',  d.users.uniqueUsers)}
            \${card('Pro users',     d.users.proUsers)}
            \${card('Cache hit rate',d.totals.cacheHitRate)}
            \${card('Retry rate',    d.totals.retryRate)}
            \${card('Error rate',    d.totals.errorRate)}
            \${card('Rate-limited',  d.totals.rateLimited)}
            \${card('Avg / user',    d.users.avgRewritesPerUser)}
            \${card('p50 latency',   d.latencyMs.p50 + ' ms')}
            \${card('p95 latency',   d.latencyMs.p95 + ' ms')}
            \${card('Est. cost',     d.cost.estimatedUSD)}
            \${card('Output tokens', d.cost.outputTokens.toLocaleString())}
        </div>

        <h2>By Mode</h2>          \${tbl(d.breakdown.byMode)}
        <h2>By Context</h2>       \${tbl(d.breakdown.byContext)}
        <h2>By Provider</h2>      \${tbl(d.breakdown.byProvider)}
        <h2>Rate Limits Hit</h2>  \${tbl(d.breakdown.rateLimitsByWindow)}
        <h2>Daily Active Users</h2> \${tbl(d.users.dailyActive)}
    \`
}
</script>
</body></html>`)
})

// ─── /webhook/payment - Webhook endpoint — called by LemonSqueezy on payment ──────────────────────────────────────────────────────────────────

app.post('/webhook/payment', express.raw({
    type: 'application/json'
}), (req, res) => {

    // ── Signature Verification ────────────────────────────────────
    // Lemon Squeezy signs every webhook with HMAC-SHA256
    // We verify it to make sure the request is genuinely from them
    // and not from someone trying to fake a payment
    const secret = process.env.WEBHOOK_SECRET
    const signature = req.headers['x-signature']

    if (!secret) {
        console.error('[webhook] ⚠️  WEBHOOK_SECRET not set — rejecting all webhooks')
        return res.status(500).json({
            error: 'Webhook secret not configured'
        })
    }

    if (!signature) {
        console.warn('[webhook] ❌ No signature header — rejecting')
        return res.status(401).json({
            error: 'Missing signature'
        })
    }

    // Compute expected signature from raw request body
    const hmac = crypto.createHmac('sha256', secret)
    const digest = hmac.update(req.body).digest('hex')

    // Constant-time comparison — prevents timing attacks
    const trusted = Buffer.from(digest, 'hex')
    const received = Buffer.from(signature, 'hex')

    if (trusted.length !== received.length ||
        !crypto.timingSafeEqual(trusted, received)) {
        console.warn('[webhook] ❌ Invalid signature — rejecting')
        return res.status(401).json({
            error: 'Invalid signature'
        })
    }

    // ── Parse Body ────────────────────────────────────────────────
    // Body is raw buffer at this point — parse it to JSON now
    let event
    try {
        event = JSON.parse(req.body.toString())
    } catch (e) {
        console.error('[webhook] ❌ Could not parse body:', e.message)
        return res.status(400).json({
            error: 'Invalid JSON'
        })
    }

    const eventName = event.meta?.event_name
    const uid = event.meta?.custom_data?.uid

    console.log(`[webhook] ✅ Verified | Event: ${eventName} | uid: ${uid?.substring(0, 8) ?? 'none'}...`)

    // ── New subscription created ──────────────────────────────────
    if (eventName === 'subscription_created') {
        if (uid) {
            const expiresAt = Date.now() + (35 * 24 * 60 * 60 * 1000)
            paidUsers.set(uid, expiresAt)
            savePaidUsers()
            console.log(`[payment] ✅ Pro granted until: ${new Date(expiresAt).toISOString()}`)
        } else {
            console.warn('[webhook] subscription_created — no uid in custom_data')
        }
    }

    // ── Subscription renewed ──────────────────────────────────────
    if (eventName === 'subscription_payment_success') {
        if (uid) {
            const expiresAt = Date.now() + (35 * 24 * 60 * 60 * 1000)
            paidUsers.set(uid, expiresAt)
            savePaidUsers()
            console.log(`[payment] ✅ Pro renewed until: ${new Date(expiresAt).toISOString()}`)
        }
    }

    // ── Subscription cancelled ────────────────────────────────────
    // Honour the remaining paid period — do NOT revoke immediately
    if (eventName === 'subscription_cancelled') {
        if (uid) {
            const endsAt = event.data?.attributes?.ends_at ||
                event.data?.attributes?.renews_at

            if (endsAt) {
                const expiresAt = new Date(endsAt).getTime()
                paidUsers.set(uid, expiresAt)
                savePaidUsers()
                console.log(`[payment] Cancelled — pro until: ${endsAt}`)
            } else {
                // Fallback — give 30 days if period end date missing
                const expiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000)
                paidUsers.set(uid, expiresAt)
                savePaidUsers()
                console.log(`[payment] Cancelled — fallback 30 day grace`)
            }
        }
    }

    // ── Subscription fully expired ────────────────────────────────
    // Period has ended — safe to revoke access now
    if (eventName === 'subscription_expired') {
        if (uid) {
            paidUsers.delete(uid)
            savePaidUsers()
            console.log(`[payment] Expired — pro revoked: ${uid?.substring(0, 8)}...`)
        }
    }

    // ── Payment failed after all retries ──────────────────────────
    if (eventName === 'subscription_payment_failed') {
        if (uid) {
            // 3 day grace period to update card details
            const expiresAt = Date.now() + (3 * 24 * 60 * 60 * 1000)
            paidUsers.set(uid, expiresAt)
            savePaidUsers()
            console.log(`[payment] Failed — 3 day grace: ${uid?.substring(0, 8)}...`)
        }
    }

    res.sendStatus(200)
})


// ─── /make-pro ──────────────────────────────────────────────────────────────────
app.post('/admin/make-pro', (req, res) => {
    if (req.body.password !== process.env.ADMIN_PASSWORD) {
        return res.status(403).json({
            error: 'no'
        })
    }
    const expiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000)
    paidUsers.set(req.body.uid, expiresAt)
    savePaidUsers()
    res.json({
        success: true,
        proUsers: paidUsers.size
    })
})

// ─── /pro-status ──────────────────────────────────────────────────────────────────
app.get('/pro-status', (req, res) => {
    const uid = req.query.uid
    const isPro = isUserPro(uid)
    const expiresAt = uid ? paidUsers.get(uid) : null

    res.json({
        isPro,
        // Tell the app when access expires so it can show the user
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null
    })
})

// ─── /get all pro users──────────────────────────────────────────────────────────────────

app.get('/debug/users', (req, res) => {
    res.json(Object.fromEntries(paidUsers))
})

// ─── /remove-pro ───────────────────────────────────────────────────────────────
app.post('/admin/remove-pro', (req, res) => {
    const {
        uid,
        password
    } = req.body

    if (password !== process.env.ADMIN_PASSWORD) {
        return res.status(403).json({
            error: 'no'
        })
    }

    if (!uid) {
        return res.status(400).json({
            error: 'uid_required'
        })
    }

    if (!paidUsers.has(uid)) {
        return res.status(404).json({
            error: 'user_not_found'
        })
    }

    paidUsers.delete(uid)
    savePaidUsers()

    console.log(`[admin] Removed pro access for uid: ${uid.substring(0, 8)}...`)

    res.json({
        success: true,
        message: 'Pro access removed',
        remainingProUsers: paidUsers.size
    })
})

// ─── /checkout lemon squeezy ──────────────────────────────────────────────────────────────────

app.get('/checkout-url', (req, res) => {
    const uid = req.query.uid || ''
    const baseURL = process.env.LEMON_CHECKOUT_URL || ''

    if (!baseURL) {
        return res.status(503).json({
            error: 'Checkout not configured'
        })
    }

    const checkoutURL = `${baseURL}?checkout[custom][uid]=${uid}`
    res.json({
        url: checkoutURL
    })
})

// ─── /health ──────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
    const uptimeHours = ((Date.now() - stats.startTime) / 3600000).toFixed(1)

    // Cost estimate: Haiku ~$0.25/M input + $1.25/M output, avg ~$0.75/M
    const estimatedCost = ((stats.estimatedTokens / 1_000_000) * 0.75).toFixed(4)

    res.json({
        status: 'ok',
        service: 'keymo-proxy',
        provider: CONFIG.provider,
        model: CONFIG.provider === 'anthropic' ? CONFIG.anthropicModel : CONFIG.openaiModel,
        uptime: `${uptimeHours}h`,
        limits: {
            perMinute: CONFIG.minuteLimit,
            perHour: CONFIG.hourLimit,
            perDay: CONFIG.dayLimit
        },
        stats: {
            totalRequests: stats.totalRequests,
            cacheHits: stats.cacheHits,
            cacheHitRate: stats.totalRequests > 0 ?
                `${((stats.cacheHits / stats.totalRequests) * 100).toFixed(1)}%` : '0%',
            rateLimitBlocks: stats.rateLimitBlocks,
            abuseBlocks: stats.abuseBlocks,
            errors: stats.errors,
            estimatedTokens: stats.estimatedTokens,
            estimatedCostUSD: `$${estimatedCost}`
        },
        cache: {
            entries: responseCache.size,
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
