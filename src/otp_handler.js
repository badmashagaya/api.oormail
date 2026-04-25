// --- CONFIGURATION & SECURITY ---
const BASE_URL = "https://api.guerrillamail.com/ajax.php";
const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const MASTER_API_KEY = "OTTONTENT"; 

// --- IN-MEMORY QUEUE MANAGER ---
const emailQueues = new Map();

async function runQueuedTask(email, taskPromiseFn) {
  if (!emailQueues.has(email)) {
    emailQueues.set(email, Promise.resolve());
  }
  
  let result, error;
  const previousTask = emailQueues.get(email);
  
  const nextTask = previousTask.then(async () => {
    try {
      result = await taskPromiseFn();
    } catch (e) {
      error = e;
    }
  });
  
  emailQueues.set(email, nextTask);
  await nextTask;
  
  if (emailQueues.get(email) === nextTask) {
    emailQueues.delete(email);
  }
  
  if (error) throw error;
  return result;
}

// --- OTPAUTH POLYFILL ---
const OTPAuth = {
  TOTP: class {
    constructor({ issuer = "", algorithm = "SHA1", digits = 6, period = 30, secret }) {
      this.algorithm = algorithm === 'SHA256' ? 'SHA-256' : algorithm === 'SHA512' ? 'SHA-512' : 'SHA-1';
      this.digits = digits;
      this.period = period;
      this.secret = secret;
      this.issuer = issuer;
    }

    async generate() {
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      let bits = 0, value = 0, index = 0;
      const decodedSecret = new Uint8Array((this.secret.length * 5) / 8);
      
      for (let i = 0; i < this.secret.length; i++) {
        const char = this.secret.charAt(i).toUpperCase();
        const val = alphabet.indexOf(char);
        if (val === -1) continue; 
        value = (value << 5) | val;
        bits += 5;
        if (bits >= 8) {
          decodedSecret[index++] = (value >>> (bits - 8)) & 255;
          bits -= 8;
        }
      }
      
      const decoded = decodedSecret.slice(0, index);
      const epoch = Math.floor(Date.now() / 1000);
      const timeStep = Math.floor(epoch / this.period);
      
      const timeBuffer = new ArrayBuffer(8);
      const timeDataView = new DataView(timeBuffer);
      timeDataView.setUint32(4, timeStep, false); 
      
      const key = await crypto.subtle.importKey(
        "raw", decoded, { name: "HMAC", hash: { name: this.algorithm } }, false, ["sign"]
      );
      
      const signature = await crypto.subtle.sign("HMAC", key, timeBuffer);
      const hmacResult = new Uint8Array(signature);
      
      const offset = hmacResult[hmacResult.length - 1] & 0xf;
      const binary =
        ((hmacResult[offset] & 0x7f) << 24) |
        ((hmacResult[offset + 1] & 0xff) << 16) |
        ((hmacResult[offset + 2] & 0xff) << 8) |
        (hmacResult[offset + 3] & 0xff);
        
      const divisor = Math.pow(10, this.digits);
      return (binary % divisor).toString().padStart(this.digits, '0');
    }
  }
};

// --- MAIN ROUTER ---
export async function handleOtpRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const platformParam = (url.searchParams.get("platform") || "").toLowerCase();

  if (request.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, x-api-key"
      }
    });
  }
  
  const providedKey = request.headers.get("x-api-key");
  if (providedKey !== MASTER_API_KEY) {
    return jsonResponse({ error: "Unauthorized access." }, 401);
  }

  if (path.endsWith("/otp")) {
    if (platformParam === "netflix") return await processNetflix(url, false);
    if (platformParam === "primevideo") return await processPrimeTotp(request, url);
    if (platformParam === "netflix-household") return await processNetflix(url, true);
    return jsonResponse({ error: "Missing or unsupported platform parameter." }, 400);
  } 
  
  if (path.endsWith("/household")) {
    return await processNetflix(url, true);
  }

  if (path.endsWith("/prime-totp")) {
    return await processPrimeTotp(request, url);
  }

  return jsonResponse({ error: "Endpoint not found." }, 404);
}

// --- NETFLIX LOGIC (Unified Standard & Household) ---
async function processNetflix(url, isHousehold = false) {
  const mailParam = url.searchParams.get("mail");
  const useQueue = url.searchParams.get("queue") === "true"; 

  if (!mailParam || !mailParam.includes("@")) return jsonResponse({ error: "Invalid email." }, 400);

  const userPart = mailParam.split("@")[0].toLowerCase();

  const fetchLogic = async () => {
    const sessionData = await callOorApi({ f: "get_email_address" });
    const sidToken = sessionData.sid_token;
    if (!sidToken) throw new Error("No session token.");

    await callOorApi({ f: "set_email_user", email_user: userPart, sid_token: sidToken });

    const inboxData = await callOorApi({ f: "get_email_list", sid_token: sidToken, offset: 0 });
    const msgList = inboxData.list || [];

    if (msgList.length === 0) return jsonResponse({ status: "empty", message: "Inbox empty" });

    // 1. BROAD CATCH: Inspects subject OR excerpt, catching blank-subject anomalies from forwards.
    const candidates = msgList.filter(msg => {
      const sub = (msg.mail_subject || "").toLowerCase().trim();
      const excerpt = (msg.mail_excerpt || "").toLowerCase().trim();

      if (isHousehold) {
        return sub.includes("temporary access") || 
               excerpt.includes("temporary access") || 
               excerpt.includes("netflix") ||
               sub === ""; 
      } else {
        return sub.includes("sign-in code") || 
               excerpt.includes("sign-in") || 
               excerpt.includes("netflix") ||
               sub === ""; 
      }
    });

    if (candidates.length === 0) return jsonResponse({ status: "not_found", message: "No applicable Netflix emails found." });

    const topCandidates = candidates.slice(0, 3);
    const promises = topCandidates.map(async (msg) => {
      const subject = unescapeHtml(msg.mail_subject || "");

      if (isHousehold) {
        // --- HOUSEHOLD EXTRACTION LOGIC (Deep Source Verification) ---
        const bodyData = await callOorApi({ f: "fetch_email", sid_token: sidToken, email_id: msg.mail_id });
        let rawBody = bodyData.mail_body || "";
        
        // Clean quoted-printable artifacts to reveal the true text
        rawBody = rawBody.replace(/=\r?\n/g, '').replace(/=3D/g, '=').replace(/&amp;/g, '&');
        
        // 2. DEEP VERIFICATION: Find the unique travel link directly
        const linkMatch = rawBody.match(/https:\/\/(?:www\.)?netflix\.com\/account\/travel\/verify[^\s"'><]+/i);

        if (linkMatch) {
          const travelUrl = linkMatch[0];
          try {
            const netflixRes = await fetch(travelUrl, {
              headers: { 
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
              }
            });
            const netflixHtml = await netflixRes.text();
            const code = extractNetflixHouseholdCode(netflixHtml);

            if (code) {
              return {
                found: true,
                code: code,
                subject: subject || "Netflix Household Code (Forwarded)", 
                date_time: convertToIST(msg.mail_timestamp),
                timestamp: msg.mail_timestamp
              };
            }
          } catch (e) {
            // Silently fail to let the next candidate attempt extraction
          }
        }
        return { found: false };

      } else {
        // --- STANDARD OTP EXTRACTION LOGIC ---
        const bodyData = await callOorApi({ f: "fetch_email", sid_token: sidToken, email_id: msg.mail_id });
        let rawBody = bodyData.mail_body || "";
        
        const isFromNetflix = /info@account\.netflix\.com/i.test(rawBody);
        if (subject === "" && !isFromNetflix) return { found: false };

        const code = extractNetflixBody(rawBody);

        if (code) {
          return {
            found: true,
            code: code,
            subject: subject || "Netflix Sign-In Code (Forwarded)",
            date_time: convertToIST(msg.mail_timestamp),
            timestamp: msg.mail_timestamp
          };
        }
        return { found: false };
      }
    });

    const results = await Promise.all(promises);
    const validResults = results.filter(r => r.found).sort((a, b) => b.timestamp - a.timestamp);

    if (validResults.length > 0) {
      const latest = validResults[0];
      return jsonResponse({
        status: "success",
        platform: isHousehold ? "netflix-household" : "netflix",
        email: mailParam,
        code: latest.code,
        date_time: latest.date_time
      });
    }

    return jsonResponse({ status: "not_found", message: "Extraction failed. The Netflix link may have expired." });
  };

  try {
    if (useQueue) return await runQueuedTask(mailParam, fetchLogic);
    return await fetchLogic();
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

// --- PRIME VIDEO TOTP LOGIC (Waits for Fresh 30s) ---
async function processPrimeTotp(request, url) {
  try {
    let secret = null;

    if (request.method === "POST") {
      const payload = await request.json();
      secret = payload.secret;
    } else if (request.method === "GET") {
      secret = url.searchParams.get("secret");
    }

    if (!secret) return jsonResponse({ error: "Missing TOTP secret in request." }, 400);

    secret = String(secret).replace(/\s+/g, '').replace(/[^A-Z2-7]/gi, '');

    const msSinceEpoch = Date.now();
    const msIntoWindow = msSinceEpoch % 30000;
    const msRemaining = 30000 - msIntoWindow;

    if (msRemaining < 28000) {
       await new Promise(resolve => setTimeout(resolve, msRemaining));
    }

    const totp = new OTPAuth.TOTP({
      issuer: "your-app.com",
      algorithm: "SHA1", 
      digits: 6,
      period: 30,
      secret: secret 
    });

    const otpCode = await totp.generate();

    return jsonResponse({
      id: crypto.randomUUID(),
      platform: "primevideo",
      otp: otpCode,
      expiresAt: "30s" 
    });

  } catch (e) {
    return jsonResponse({ 
      error: "Failed to generate TOTP", 
      details: e.message || "Unknown cryptographic or parsing error" 
    }, 500);
  }
}

// --- HELPERS & EXTRACTION ---
async function callOorApi(params) {
  const url = new URL(BASE_URL);
  params.ip = "127.0.0.1"; params.agent = "OOR_Mail_Client";
  Object.keys(params).forEach(key => url.searchParams.append(key, params[key]));
  
  const headers = { "User-Agent": USER_AGENT };
  if (params.sid_token) headers["Cookie"] = `PHPSESSID=${params.sid_token}`;

  const response = await fetch(url, { headers });
  return await response.json();
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    status: status
  });
}

function convertToIST(unixTimestamp) {
  if (!unixTimestamp) return "Unavailable";
  const date = new Date(unixTimestamp * 1000);
  return date.toLocaleString("en-IN", { timeZone: "Asia/Kolkata", hour12: true });
}

function unescapeHtml(str) {
  if (!str) return "";
  return str.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#039;/g, "'").replace(/&nbsp;/g, " ");
}

function extractNetflixHouseholdCode(htmlContent) {
  // 1. JSON Data Extraction (www_netflix_com_source.html)
  const jsonMatch = htmlContent.match(/"challengeOtp"\s*:\s*\{[^}]*"value"\s*:\s*"(\d{4,6})"/);
  if (jsonMatch) return jsonMatch[1];

  // 2. Fallback HTML Element Extraction
  const divMatch = htmlContent.match(/data-uia="travel-verification-otp"[^>]*>\s*(\d{4,6})\s*</);
  if (divMatch) return divMatch[1];
  
  // 3. Ultra-Fallback Class Extraction
  const classMatch = htmlContent.match(/class="[^"]*challenge-code[^"]*"[^>]*>\s*(\d{4,6})\s*</);
  if (classMatch) return classMatch[1];

  return null;
}

function extractNetflixBody(htmlContent) {
  const cleanHtml = unescapeHtml(htmlContent || "");
  const textOnly = cleanHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
  const htmlMatch = cleanHtml.match(/class="[^"]*lrg-number[^"]*".*?>\s*(\d{4,6})\s*</);
  if (htmlMatch) return htmlMatch[1];
  const textMatch = textOnly.match(/Enter this code.*?(\d{4,6})/);
  if (textMatch) return textMatch[1];
  return null;
}
