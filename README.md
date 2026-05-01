# 🔐 Keymo Proxy Server

Secure backend proxy for Keymo AI requests.

---

## 🚀 Purpose

* Protect API keys
* Add rate limiting
* Reduce cost via caching
* Prevent abuse

---

## ⚙️ Setup

### 1. Install dependencies

```bash
npm install
```

---

### 2. Add environment variable

```bash
ANTHROPIC_API_KEY=your-api-key
```

---

### 3. Run server

```bash
node index.js
```

---

## 🌐 API Endpoint

POST `/rewrite`

### Request:

```json
{
  "text": "your input",
  "mode": "professional"
}
```

---

### Response:

```json
{
  "result": "rewritten text"
}
```

---

## 🧠 Features

* Rate limiting (per user)
* Daily usage cap
* In-memory caching
* Input validation

---

## ⚠️ Limits

* Max text length: 500 chars
* Max requests/day: 100 (MVP)

---

## 🚀 Deployment

Deploy on Railway:

1. Push to GitHub
2. Connect repo to Railway
3. Add environment variable
4. Deploy

---

## 🔐 Security Notes

* Never expose API keys in frontend
* Always use proxy for LLM calls

---

## 💡 Future Improvements

* Redis cache
* User authentication
* Usage analytics
