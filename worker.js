// @ts-nocheck

// =====================================================================
// 🔐 [SECURITY] Helper Functions (Session Token / Password Hash / Utils)
// ---------------------------------------------------------------------
// ต้องตั้งค่า Secret ใน Cloudflare ก่อน Deploy:
//   wrangler secret put AUTH_SECRET          (สุ่มข้อความยาว ๆ อย่างน้อย 32 ตัวอักษร)
//   wrangler secret put OTP_INTERNAL_SECRET  (ต้องตรงกับค่าที่ Code.gs ส่งมา)
// =====================================================================
const TOKEN_TTL_SEC = 30 * 24 * 60 * 60;   // อายุ Session Token (30 วัน)
const PBKDF2_ITERATIONS = 100000;          // Cloudflare Workers รองรับสูงสุด 100,000
const LEGACY_OTP_SECRET = "MT_GMAIL_SECURE_99"; // ใช้ชั่วคราวจนกว่าจะตั้ง OTP_INTERNAL_SECRET
const R2_PUBLIC_URL = "https://pub-60abb993c7fc47f79ccea4b4c12dbde5.r2.dev/";
const D1_MAX_PARAMS = 90;                  // D1 จำกัด Bound Parameters ไม่เกิน 100 ต่อ Query

// Endpoint ที่เรียกได้โดยไม่ต้อง Login
const PUBLIC_PATHS = new Set(["/login", "/register", "/verify-otp", "/generate-otp-internal"]);
// Endpoint ที่เฉพาะ Administrator เท่านั้น
const ADMIN_PATHS = new Set(["/getUsers", "/updateUserRoleStatus", "/getLogs"]);
const VALID_ROLES = ["Administrator", "Editor", "Subscriber"];
const VALID_STATUSES = ["Pending", "Approved", "Suspended"];
const BLOCKED_STATUSES = ["Pending", "Suspended"];
const SENSITIVE_USER_FIELDS = ["password", "otp_code", "otp_expiry"];

const textEncoder = new TextEncoder();

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64UrlEncode(bytes) {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64UrlDecode(str) {
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return b64ToBytes(b64);
}

// เปรียบเทียบแบบ Constant-time ป้องกัน Timing Attack
function timingSafeEqualBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function timingSafeEqualStr(a, b) {
  return timingSafeEqualBytes(textEncoder.encode(String(a ?? "")), textEncoder.encode(String(b ?? "")));
}

async function hmacSha256(secret, data) {
  const key = await crypto.subtle.importKey("raw", textEncoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, textEncoder.encode(data)));
}

async function signToken(payload, secret) {
  const body = b64UrlEncode(textEncoder.encode(JSON.stringify(payload)));
  const sig = b64UrlEncode(await hmacSha256(secret, body));
  return `${body}.${sig}`;
}

async function verifyToken(token, secret) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  try {
    const expected = await hmacSha256(secret, body);
    if (!timingSafeEqualBytes(expected, b64UrlDecode(sig))) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64UrlDecode(body)));
    if (!payload || !payload.uid || !payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

async function issueToken(userId, role, secret) {
  return signToken({ uid: userId, role: role, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SEC }, secret);
}

function getBearerToken(request) {
  const h = request.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.substring(7).trim() : "";
}

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", textEncoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${bytesToB64(salt)}$${bytesToB64(hash)}`;
}

// คืนค่า { ok, needsRehash } — รองรับรหัสผ่านเดิมที่เก็บเป็น Plaintext (จะถูก Hash ใหม่อัตโนมัติเมื่อ Login สำเร็จ)
async function verifyPassword(password, stored) {
  if (!stored || !password) return { ok: false, needsRehash: false };
  const s = String(stored);
  if (s.startsWith("pbkdf2$")) {
    const parts = s.split("$");
    if (parts.length !== 4) return { ok: false, needsRehash: false };
    const iterations = parseInt(parts[1], 10);
    const salt = b64ToBytes(parts[2]);
    const expected = b64ToBytes(parts[3]);
    const actual = await pbkdf2(password, salt, iterations);
    return { ok: timingSafeEqualBytes(actual, expected), needsRehash: iterations !== PBKDF2_ITERATIONS };
  }
  // Legacy plaintext
  return { ok: timingSafeEqualStr(password, s), needsRehash: true };
}

// สุ่ม OTP ด้วย Crypto RNG (แทน Math.random ที่เดาได้)
function generateOtp(length = 5) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const limit = 256 - (256 % chars.length); // ป้องกัน modulo bias
  let otp = "";
  while (otp.length < length) {
    const buf = crypto.getRandomValues(new Uint8Array(16));
    for (const b of buf) {
      if (b < limit && otp.length < length) otp += chars[b % chars.length];
    }
  }
  return otp;
}

// อ่านค่าคอลัมน์แบบไม่สนตัวพิมพ์เล็ก/ใหญ่ (เช่น status / Status)
function col(row, name) {
  if (!row) return undefined;
  if (row[name] !== undefined) return row[name];
  const lower = name.toLowerCase();
  const k = Object.keys(row).find(key => key.toLowerCase() === lower);
  return k !== undefined ? row[k] : undefined;
}

function stripSensitive(obj) {
  if (!obj || typeof obj !== "object") return obj;
  Object.keys(obj).forEach(k => {
    if (SENSITIVE_USER_FIELDS.includes(k.toLowerCase())) delete obj[k];
  });
  return obj;
}

// รวม JSON_Data + คอลัมน์หลัก แล้วลบข้อมูลลับก่อนส่งให้หน้าเว็บ
function buildPublicUser(row) {
  let parsedJson = {};
  try { if (row.JSON_Data) parsedJson = JSON.parse(row.JSON_Data) || {}; } catch (e) { }
  const userData = { ...parsedJson, ...row };
  delete userData.JSON_Data;
  const role = col(row, "role");
  const status = col(row, "status");
  const pageAccess = col(row, "PageAccess");
  if (role) userData.role = role;
  if (status) userData.status = status;
  if (pageAccess !== null && pageAccess !== undefined) userData.PageAccess = pageAccess;
  return stripSensitive(userData);
}

function chunkArray(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

function safeJsonParse(str, fallback = null) {
  try { return JSON.parse(str); } catch (e) { return fallback; }
}

function sanitizeFileName(name) {
  return String(name || "file").replace(/[^A-Za-z0-9._-]/g, "_").substring(0, 120);
}

const ALLOWED_IMAGE_EXT = { "image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg", "image/webp": "webp", "image/gif": "gif" };
const MAX_UPLOAD_BYTES = 15 * 1024 * 1024; // 15MB ต่อไฟล์

function base64ToBytesSafe(base64Data) {
  let data = String(base64Data || "");
  if (data.includes(",")) data = data.split(",")[1];
  return b64ToBytes(data);
}

export default {
  async fetch(request, env) {
    // ==========================================
    // 1. ตั้งค่า CORS (อนุญาตให้ Frontend เรียก API ได้)
    // ==========================================
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS, PUT, DELETE",
      "Access-Control-Max-Age": "86400",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // ==========================================
      // [NEW] เสิร์ฟหน้าเว็บหลักผ่าน Iframe (เพื่อครอบ Custom Domain)
      // ==========================================
      if (request.method === "GET" && path === "/") {
        // 🛑 นำลิงก์ Web App ของ Google Apps Script (ที่ลงท้ายด้วย /exec) ของคุณมาใส่ที่นี่
        const gasUrl = "https://script.google.com/macros/s/AKfycbx_fnGOppT2woV11n_sS5qvcicYJeIIH9ATyo3IaQtYvSfnuCbeQ93R9qOHl16-A3H-/exec"; 
        
        const html = `
          <!DOCTYPE html>
          <html lang="th">
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
              <title>MT | Pre-Order</title>
              <style>
                body, html { margin: 0; padding: 0; width: 100%; height: 100%; overflow: hidden; background-color: #f5f5f7; }
                iframe { width: 100%; height: 100%; border: none; display: block; }
              </style>
            </head>
            <body>
              <iframe src="${gasUrl}" allow="clipboard-read; clipboard-write"></iframe>
            </body>
          </html>
        `;

        return new Response(html, {
          headers: { 
            "Content-Type": "text/html;charset=UTF-8",
            "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate"
          }
        });
      }

      // ==========================================
      // 2.1 API Endpoint: /getBaseData (ข้อมูลพื้นฐาน: Config, Categories, Products)
      // ==========================================
      if (request.method === "GET" && path === "/getBaseData") {
        const [configRes, categoriesRes, productsRes] = await Promise.all([
          env.DB.prepare("SELECT * FROM Config").all(),
          env.DB.prepare("SELECT * FROM Categories").all(),
          env.DB.prepare("SELECT * FROM Products").all()
        ]);

        let appData = { config: {}, categories: [], products: [] };

        if (configRes.results && configRes.results.length > 0) {
          const systemConfig = configRes.results.find(row => row.KeyName === 'system_settings');
          if (systemConfig) {
            try { appData.config = JSON.parse(systemConfig.JSON_Data); } catch (e) { }
          }
        }

        if (categoriesRes.results) {
          appData.categories = categoriesRes.results.map(row => {
            try { return JSON.parse(row.JSON_Data); } catch (e) { return null; }
          }).filter(Boolean);
        }

        if (productsRes.results) {
          appData.products = productsRes.results.map((row, index) => {
            try {
              let p = JSON.parse(row.JSON_Data);
              p._rowIndex = index + 2;
              return p;
            } catch (e) { return null; }
          }).filter(Boolean);
        }

        return new Response(JSON.stringify(appData), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 2.2 API Endpoint: /getPoData (ข้อมูลไฟล์สั่งซื้อ)
      // ==========================================
      if (request.method === "GET" && path === "/getPoData") {
        const poRes = await env.DB.prepare("SELECT * FROM PurchaseOrders").all();
        let poData = [];
        if (poRes.results) {
          poData = poRes.results.map(row => {
            try { return JSON.parse(row.JSON_Data); } catch (e) { return null; }
          }).filter(Boolean);
        }
        return new Response(JSON.stringify({ purchaseOrders: poData }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 2.3 API Endpoint: /getLogisticsData (ข้อมูลจัดส่งและติดตาม)
      // ==========================================
      if (request.method === "GET" && path === "/getLogisticsData") {
        const [shipmentsRes, trackingRes, grRes] = await Promise.all([
          env.DB.prepare("SELECT * FROM Shipments").all(),
          env.DB.prepare("SELECT * FROM TrackingNotes").all(),
          env.DB.prepare("SELECT * FROM GoodsReceipts").all()
        ]);

        let logisData = { shipments: [], trackingNotes: [], goodsReceipts: [] };

        if (shipmentsRes.results) {
          logisData.shipments = shipmentsRes.results.map(row => {
            try { return JSON.parse(row.JSON_Data); } catch (e) { return null; }
          }).filter(Boolean);
        }

        if (trackingRes.results) {
          logisData.trackingNotes = trackingRes.results.map(row => {
            try {
              return {
                id: row.Note_ID, searchRef: row.SearchRef, history: JSON.parse(row.History_JSON), lastUpdate: row.UpdatedAt
              };
            } catch (e) { return null; }
          }).filter(Boolean);
        }

        if (grRes.results) {
          logisData.goodsReceipts = grRes.results.map(row => {
            try {
              let dateArray = JSON.parse(row.DownloadDates_JSON || "[]");
              return {
                grId: row.GR_ID, downloadDates: dateArray, downloadDate: dateArray.length > 0 ? dateArray[dateArray.length - 1] : "",
                driveUrl: row.Drive_URL, lots: JSON.parse(row.DownloadedLots_JSON || "[]"), isOutdated: row.Is_Outdated === 1
              };
            } catch (e) { return null; }
          }).filter(Boolean);
        }

        return new Response(JSON.stringify(logisData), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 3. API Endpoint: /saveCategory (เพิ่มหมวดหมู่)
      // ==========================================
      if (request.method === "POST" && path === "/saveCategory") {
        try {
            const body = await request.json();
            
            const stockType = body.stockType || 'preorder';
            const prefixNum = stockType === 'ready' ? 2 : (stockType === 'preorder_bkk' ? 3 : 1);

            const allCats = await env.DB.prepare("SELECT JSON_Data FROM Categories").all();
            let maxNum = 0;
            
            if (allCats && allCats.results) {
                allCats.results.forEach(row => {
                    let pData = {};
                    try { 
                        let parsed = JSON.parse(row.JSON_Data); 
                        if (parsed && typeof parsed === 'object') pData = parsed;
                    } catch(e) {}
                    
                    let cType = pData.stockType || 'preorder';
                    
                    if (cType === stockType) {
                        let numStr = String(pData.numberCode || pData.NumberCode || '');
                        let n = 0;
                        if (numStr.length === 4) {
                            n = parseInt(numStr.substring(1));
                        } else if (numStr.length > 0) {
                            n = parseInt(numStr);
                        }
                        if (!isNaN(n) && n > maxNum) maxNum = n;
                    }
                });
            }
            
            const numberCode = String(prefixNum) + String(maxNum + 1).padStart(3, '0');

            const catObj = {
              catCode: body.catCode,
              name: body.name,
              numberCode: numberCode,
              stockType: stockType
            };

            // 🌟 สร้างรหัสเฉพาะของระบบฐานข้อมูล เพื่อหลบการซ้ำกัน (เช่น SH_ready)
            const dbCatCode = catObj.catCode + "_" + stockType; 

            // 🌟 บันทึกโดยส่ง dbCatCode และ catObj.numberCode เข้าไปให้ครบ
            await env.DB.prepare("INSERT INTO Categories (CatCode, NumberCode, JSON_Data) VALUES (?, ?, ?)")
              .bind(dbCatCode, catObj.numberCode, JSON.stringify(catObj))
              .run();

            return new Response(JSON.stringify(catObj), {
              status: 200,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
            
        } catch (err) {
            console.error("Save Category Error:", err);
            return new Response(JSON.stringify({ success: false, message: err.message }), {
              status: 500,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
        }
      }

      // ==========================================
      // 4. API Endpoint: /saveProductsBatch (เพิ่มสินค้าทีละหลายรายการ)
      // ==========================================
      if (request.method === "POST" && path === "/saveProductsBatch") {
        const body = await request.json();
        let products = body.products;

        const stmt = env.DB.prepare("INSERT INTO Products (UID, SKU, JSON_Data) VALUES (?, ?, ?)");
        const batchStmts = products.map(p => stmt.bind(p.uid, p.sku, JSON.stringify(p)));

        await env.DB.batch(batchStmts);

        return new Response(JSON.stringify({ success: true, message: "บันทึกสินค้าใหม่เรียบร้อย" }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 5. API Endpoint: /updateProduct (แก้ไขข้อมูลสินค้า 1 รายการ)
      // ==========================================
      if (request.method === "POST" && path === "/updateProduct") {
        const body = await request.json();
        let product = body.product;

        delete product._tempLiveCount;
        delete product._tempCodeCount;

        await env.DB.prepare("UPDATE Products SET SKU = ?, JSON_Data = ?, UpdatedAt = CURRENT_TIMESTAMP WHERE UID = ?")
          .bind(product.sku, JSON.stringify(product), product.uid)
          .run();

        return new Response(JSON.stringify({ success: true, message: "อัปเดตข้อมูลสำเร็จ" }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 6. API Endpoint: /deleteProductsBatch (ลบสินค้าหลายรายการ)
      // ==========================================
      if (request.method === "POST" && path === "/deleteProductsBatch") {
        const body = await request.json();
        let uidArray = body.uids;

        const placeholders = uidArray.map(() => '?').join(',');
        const query = `DELETE FROM Products WHERE UID IN (${placeholders})`;

        await env.DB.prepare(query).bind(...uidArray).run();

        return new Response(JSON.stringify({ success: true, message: `ลบข้อมูลสำเร็จ ${uidArray.length} รายการ` }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 7. API Endpoint: /savePurchaseOrdersBatch (บันทึก PO หลายรายการ)
      // ==========================================
      if (request.method === "POST" && path === "/savePurchaseOrdersBatch") {
        const body = await request.json();
        let { date, category, payloads } = body;

        // 🌟 1. ลบเอกสารเก่าใน "วันที่" และ "หมวดหมู่" นี้ออกก่อน (ป้องกัน PO ซ้ำซ้อนเวลาเปลี่ยนกลุ่ม Wechat)
        if (date && category) {
          await env.DB.prepare("DELETE FROM PurchaseOrders WHERE JSON_EXTRACT(JSON_Data, '$.date') = ? AND Category = ?")
             .bind(date, category)
             .run();
        }

        // 🌟 2. บันทึกเอกสารใหม่ลงไปแทนที่
        if (payloads && payloads.length > 0) {
          const stmt = env.DB.prepare("INSERT INTO PurchaseOrders (PO_ID, PODate, Category, JSON_Data) VALUES (?, ?, ?, ?)");
          const batchStmts = payloads.map(po => stmt.bind(po.poId, po.formattedDate, po.category, JSON.stringify(po)));
          await env.DB.batch(batchStmts);
        }

        return new Response(JSON.stringify({ message: `บันทึกไฟล์สั่งซื้อสำเร็จ! (แยกเป็น ${payloads ? payloads.length : 0} เอกสาร)` }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 8. API Endpoint: /updateShipment (สร้าง/แก้ไข รายการจัดส่งพัสดุหลัก)
      // ==========================================
      if (request.method === "POST" && path === "/updateShipment") {
        const body = await request.json();
        let payload = body.payload; 

        await env.DB.prepare("INSERT INTO Shipments (Ship_ID, Ship_Date, JSON_Data) VALUES (?, ?, ?) ON CONFLICT(Ship_ID) DO UPDATE SET Ship_Date=excluded.Ship_Date, JSON_Data=excluded.JSON_Data, UpdatedAt=CURRENT_TIMESTAMP")
          .bind(payload.shipId, payload.shipDate, JSON.stringify(payload))
          .run();

        return new Response(JSON.stringify({ message: `บันทึกรายการจัดส่ง ${payload.shipId} สำเร็จ!` }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 9. API Endpoint: /deleteShipment (ลบรายการจัดส่งพัสดุ)
      // ==========================================
      if (request.method === "POST" && path === "/deleteShipment") {
        const body = await request.json();
        await env.DB.prepare("DELETE FROM Shipments WHERE Ship_ID = ?").bind(body.shipId).run();

        return new Response(JSON.stringify({ message: `ลบรายการจัดส่ง ${body.shipId} ออกจากระบบสำเร็จ!` }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 10. API Endpoint: /saveTrackingNote (บันทึกข้อความติดตาม)
      // ==========================================
      if (request.method === "POST" && path === "/saveTrackingNote") {
        const body = await request.json();
        let noteId = "TN" + new Date().getTime();
        let ts = new Date().toISOString();

        let newEntry = {
          message: body.message,
          images: body.images || [],
          replyTo: body.replyTo,
          timestamp: ts,
          user: body.user || "Admin"
        };

        const existing = await env.DB.prepare("SELECT * FROM TrackingNotes WHERE SearchRef = ?").bind(body.searchRef).first();
        let historyList = [];

        if (existing && existing.History_JSON) {
          historyList = JSON.parse(existing.History_JSON);
          noteId = existing.Note_ID;
        }

        historyList.push(newEntry);

        await env.DB.prepare("INSERT INTO TrackingNotes (Note_ID, SearchRef, History_JSON) VALUES (?, ?, ?) ON CONFLICT(Note_ID) DO UPDATE SET History_JSON=excluded.History_JSON, UpdatedAt=CURRENT_TIMESTAMP")
          .bind(noteId, body.searchRef, JSON.stringify(historyList))
          .run();

        let resData = { id: noteId, searchRef: body.searchRef, history: historyList, lastUpdate: ts };
        return new Response(JSON.stringify(resData), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 11. API Endpoint: /deleteTrackingNote (ลบข้อความติดตาม 1 ข้อความ)
      // ==========================================
      if (request.method === "POST" && path === "/deleteTrackingNote") {
        const body = await request.json();

        const existing = await env.DB.prepare("SELECT * FROM TrackingNotes WHERE SearchRef = ?").bind(body.searchRef).first();
        if (!existing) throw new Error("ไม่พบประวัติการติดตาม");

        let historyList = JSON.parse(existing.History_JSON);
        let initialLength = historyList.length;

        historyList = historyList.filter(note => note.timestamp !== body.timestamp);

        if (historyList.length < initialLength) {
          await env.DB.prepare("UPDATE TrackingNotes SET History_JSON = ?, UpdatedAt = CURRENT_TIMESTAMP WHERE Note_ID = ?")
            .bind(JSON.stringify(historyList), existing.Note_ID)
            .run();
        }

        let resData = { id: existing.Note_ID, searchRef: body.searchRef, history: historyList, lastUpdate: new Date().toISOString() };
        return new Response(JSON.stringify(resData), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 12. API Endpoint: /saveGoodsReceiptHistory (บันทึกใบตรวจรับพัสดุ)
      // ==========================================
      if (request.method === "POST" && path === "/saveGoodsReceiptHistory") {
        const body = await request.json();

        let existing = await env.DB.prepare("SELECT * FROM GoodsReceipts WHERE GR_ID = ?").bind(body.grId).first();
        let downloadDates = existing ? JSON.parse(existing.DownloadDates_JSON) : [];
        downloadDates.push(body.dateStr);

        let driveUrl = body.driveUrl || (existing ? existing.Drive_URL : "");
        let lotsJson = body.lotsJson || (existing ? existing.DownloadedLots_JSON : "[]");

        await env.DB.prepare("INSERT INTO GoodsReceipts (GR_ID, DownloadDates_JSON, Drive_URL, DownloadedLots_JSON, Is_Outdated) VALUES (?, ?, ?, ?, 0) ON CONFLICT(GR_ID) DO UPDATE SET DownloadDates_JSON=excluded.DownloadDates_JSON, Drive_URL=excluded.Drive_URL, DownloadedLots_JSON=excluded.DownloadedLots_JSON, Is_Outdated=0, UpdatedAt=CURRENT_TIMESTAMP")
          .bind(body.grId, JSON.stringify(downloadDates), driveUrl, lotsJson)
          .run();

        let resData = {
          grId: body.grId,
          downloadDates: downloadDates,
          downloadDate: body.dateStr,
          driveUrl: driveUrl,
          lots: JSON.parse(lotsJson),
          isOutdated: false
        };

        return new Response(JSON.stringify(resData), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 13. API Endpoint: /saveLog (บันทึก Log ลงฐานข้อมูล)
      // ==========================================
      if (request.method === "POST" && path === "/saveLog") {
        const body = await request.json();

        let existing = await env.DB.prepare("SELECT LogArray_JSON FROM Logs WHERE DateString = ?").bind(body.dateStr).first();
        let logArray = existing ? JSON.parse(existing.LogArray_JSON) : [];
        logArray.push(body.logEntry);

        await env.DB.prepare("INSERT INTO Logs (DateString, LogArray_JSON) VALUES (?, ?) ON CONFLICT(DateString) DO UPDATE SET LogArray_JSON=excluded.LogArray_JSON, LastUpdate=CURRENT_TIMESTAMP")
          .bind(body.dateStr, JSON.stringify(logArray))
          .run();

        await env.DB.prepare("DELETE FROM Logs WHERE DateString < date('now', '-30 days')").run();

        return new Response(JSON.stringify({ success: true }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 14. API Endpoint: /saveVrUploadData (อัปโหลดและบันทึกยอดขาย VR)
      // ==========================================
      if (request.method === "POST" && path === "/saveVrUploadData") {
        const body = await request.json();
        const uploadDate = body.uploadDate;
        const items = body.items;
        const missingSkus = body.missingSkus || [];

        const stmtSales = env.DB.prepare("INSERT INTO VrSalesData (UID, SKU, UploadDate, JSON_Data) VALUES (?, ?, ?, ?)");
        const batchSales = items.map(item =>
          stmtSales.bind(item.uid, item.sku, uploadDate, JSON.stringify(item))
        );

        if (batchSales.length > 0) {
          await env.DB.batch(batchSales);
        }

        if (missingSkus.length > 0) {
          const stmtProds = env.DB.prepare("INSERT INTO Products (UID, SKU, JSON_Data) VALUES (?, ?, ?)");
          const batchProds = missingSkus.map(skuObj => {
            let pObj = {
              uid: skuObj.uid, sku: skuObj.sku, groupCode: skuObj.catCode,
              catCode: skuObj.catCode, desc: skuObj.desc, category: "", sellDate: uploadDate
            };
            return stmtProds.bind(skuObj.uid, skuObj.sku, JSON.stringify(pObj));
          });
          await env.DB.batch(batchProds);
        }

        return new Response(JSON.stringify({ status: 'success', message: "อัปโหลดและบันทึกสำเร็จ!" }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 15. API Endpoint: /getVrSalesData (ดึงข้อมูลยอดขายทั้งหมด)
      // ==========================================
      if (request.method === "GET" && path === "/getVrSalesData") {
        const result = await env.DB.prepare("SELECT * FROM VrSalesData").all();

        let vrSales = {};
        if (result.results) {
          result.results.forEach(row => {
            let date = row.UploadDate;
            if (!vrSales[date]) vrSales[date] = [];
            try {
              vrSales[date].push(JSON.parse(row.JSON_Data));
            } catch (e) { }
          });
        }

        return new Response(JSON.stringify(vrSales), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 16. API Endpoint: /uploadImages (อัปโหลดรูปภาพลง R2)
      // ==========================================
      if (request.method === "POST" && path === "/uploadImages") {
        const body = await request.json();
        const images = body.images;

        const R2_PUBLIC_URL = "https://pub-60abb993c7fc47f79ccea4b4c12dbde5.r2.dev/";

        let uploadedUrls = [];

        for (let i = 0; i < images.length; i++) {
          let fileObj = images[i];
          let base64Data = fileObj.base64;
          if (base64Data.includes(',')) {
            base64Data = base64Data.split(',')[1];
          }

          let extension = fileObj.mime ? fileObj.mime.split('/')[1] : 'png';
          if (extension === 'jpeg') extension = 'jpg';

          let fileName = `upload_${Date.now()}_${Math.random().toString(36).substring(2, 7)}.${extension}`;

          const binaryString = atob(base64Data);
          const bytes = new Uint8Array(binaryString.length);
          for (let j = 0; j < binaryString.length; j++) {
            bytes[j] = binaryString.charCodeAt(j);
          }

          await env.R2_BUCKET.put(fileName, bytes.buffer, {
            httpMetadata: { contentType: fileObj.mime || 'image/png' }
          });

          uploadedUrls.push(R2_PUBLIC_URL + fileName);
        }

        return new Response(JSON.stringify({ success: true, urls: uploadedUrls }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // 17. API Endpoint: /getLatestSystemUpdate (เช็คการอัปเดตระบบ)
      // ==========================================
      if (request.method === "GET" && path === "/getLatestSystemUpdate") {
        const res = await env.DB.prepare("SELECT LastUpdate FROM Logs ORDER BY LastUpdate DESC LIMIT 1").first();
        let lastTimeStr = res && res.LastUpdate ? new Date(res.LastUpdate).getTime().toString() : new Date().getTime().toString();
        
        return new Response(JSON.stringify({ lastUpdate: lastTimeStr }), { 
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } 
        });
      }

      // ==========================================
      // 18. API Endpoint: /deleteVrSalesBatch (ลบข้อมูลยอดขายทีละหลายรายการ)
      // ==========================================
      if (request.method === "POST" && path === "/deleteVrSalesBatch") {
        const body = await request.json();
        const itemsToDelete = body.items;

        if (!itemsToDelete || !Array.isArray(itemsToDelete) || itemsToDelete.length === 0) {
          return new Response(JSON.stringify({ success: false, message: "ไม่มีข้อมูลสำหรับลบ" }), {
            status: 400,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        const stmt = env.DB.prepare("DELETE FROM VrSalesData WHERE UID = ? AND UploadDate = ?");
        const batchStmts = itemsToDelete.map(item => stmt.bind(item.uid, item.date));
        await env.DB.batch(batchStmts);

        return new Response(JSON.stringify({ 
          success: true, 
          message: `ลบข้อมูลยอดขายจำนวน ${itemsToDelete.length} รายการสำเร็จ` 
        }), {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        });
      }

      // ==========================================
      // 19. API Endpoint: /saveConfig (บันทึกการตั้งค่าระบบ)
      // ==========================================
      if (request.method === "POST" && path === "/saveConfig") {
        const body = await request.json();
        
        await env.DB.prepare(`
          INSERT INTO Config (KeyName, JSON_Data) 
          VALUES ('system_settings', ?) 
          ON CONFLICT(KeyName) 
          DO UPDATE SET JSON_Data=excluded.JSON_Data, UpdatedAt=CURRENT_TIMESTAMP
        `).bind(JSON.stringify(body)).run();

        return new Response(JSON.stringify({ success: true, message: "บันทึกการตั้งค่าระบบลงฐานข้อมูล Cloudflare สำเร็จ" }), {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        });
      }

      // ==========================================
      // 20. API Endpoint: /updateCategory (แก้ไขข้อมูลหมวดหมู่ แยกตามระบบ)
      // ==========================================
      if (request.method === "POST" && path === "/updateCategory") {
        try {
            const body = await request.json();
            const { oldCode, newCode, newName, stockType } = body;
            const currentStockType = stockType || 'preorder';

            // 🌟 เตรียมรหัสสำหรับดึงข้อมูล (รองรับทั้งข้อมูลเก่าที่ไม่มี _type และข้อมูลใหม่ที่มี _type ต่อท้าย)
            const dbOldCodeRaw = oldCode;
            const dbOldCodeNew = oldCode + "_" + currentStockType;
            const dbNewCode = newCode + "_" + currentStockType;

            const existing = await env.DB.prepare("SELECT * FROM Categories WHERE (CatCode = ? OR CatCode = ?) AND (JSON_EXTRACT(JSON_Data, '$.stockType') = ? OR (JSON_EXTRACT(JSON_Data, '$.stockType') IS NULL AND ? = 'preorder'))")
                .bind(dbOldCodeRaw, dbOldCodeNew, currentStockType, currentStockType)
                .first();
            
            let numberCode = "";
            
            if (!existing) {
               const prefixNum = currentStockType === 'ready' ? 2 : (currentStockType === 'preorder_bkk' ? 3 : 1);
               const allCats = await env.DB.prepare("SELECT JSON_Data FROM Categories").all();
               let maxNum = 0;
               
               if (allCats && allCats.results) {
                   allCats.results.forEach(row => {
                       let pData = {};
                       try { 
                           let parsed = JSON.parse(row.JSON_Data); 
                           if (parsed && typeof parsed === 'object') pData = parsed;
                       } catch(e) {}
                       
                       let cType = pData.stockType || 'preorder';
                       
                       if (cType === currentStockType) {
                           let numStr = String(pData.numberCode || pData.NumberCode || '');
                           let n = numStr.length === 4 ? parseInt(numStr.substring(1)) : parseInt(numStr);
                           if (!isNaN(n) && n > maxNum) maxNum = n;
                       }
                   });
               }
               numberCode = String(prefixNum) + String(maxNum + 1).padStart(3, '0');
               
               const newCatObj = {
                 catCode: newCode,
                 name: newName,
                 numberCode: numberCode,
                 stockType: currentStockType
               };
               
               // 🌟 สร้างรหัสเฉพาะของระบบฐานข้อมูล เพื่อหลบการซ้ำกัน
               const dbNewCode = newCode + "_" + currentStockType;

               await env.DB.prepare("INSERT INTO Categories (CatCode, NumberCode, JSON_Data) VALUES (?, ?, ?)")
                 .bind(dbNewCode, numberCode, JSON.stringify(newCatObj))
                 .run();
                 
            } else {
               let oldData = {};
               try { 
                   let parsed = JSON.parse(existing.JSON_Data); 
                   if (parsed && typeof parsed === 'object') oldData = parsed;
               } catch(e) {}
               numberCode = oldData.numberCode || oldData.NumberCode || existing.NumberCode;

               const updatedCatObj = {
                 catCode: newCode,
                 name: newName,
                 numberCode: numberCode,
                 stockType: currentStockType
               };

               // 🌟 ใช้รหัสฐานข้อมูลแบบใหม่ ในการ UPDATE เพื่อครอบคลุมทั้งข้อมูลเก่าและใหม่
               await env.DB.prepare("UPDATE Categories SET CatCode = ?, JSON_Data = ?, UpdatedAt = CURRENT_TIMESTAMP WHERE (CatCode = ? OR CatCode = ?) AND (JSON_EXTRACT(JSON_Data, '$.stockType') = ? OR (JSON_EXTRACT(JSON_Data, '$.stockType') IS NULL AND ? = 'preorder'))")
                 .bind(dbNewCode, JSON.stringify(updatedCatObj), dbOldCodeRaw, dbOldCodeNew, currentStockType, currentStockType)
                 .run();
            }
            
            const productsRes = await env.DB.prepare("SELECT * FROM Products WHERE (JSON_EXTRACT(JSON_Data, '$.groupCode') = ? OR JSON_EXTRACT(JSON_Data, '$.catCode') = ?) AND (JSON_EXTRACT(JSON_Data, '$.stockType') = ? OR (JSON_EXTRACT(JSON_Data, '$.stockType') IS NULL AND ? = 'preorder'))")
              .bind(oldCode, oldCode, currentStockType, currentStockType)
              .all();
              
            if (productsRes.results && productsRes.results.length > 0) {
                const updateProductStmt = env.DB.prepare("UPDATE Products SET JSON_Data = ?, UpdatedAt = CURRENT_TIMESTAMP WHERE UID = ?");
                let batchStmts = [];
                
                productsRes.results.forEach(row => {
                    let pData = {};
                    try {
                        let parsed = JSON.parse(row.JSON_Data);
                        if (parsed && typeof parsed === 'object') {
                            pData = parsed;
                            let isModified = false;
                            
                            if (pData.groupCode === oldCode) {
                                pData.groupCode = newCode;
                                isModified = true;
                            }
                            if (pData.catCode === oldCode) {
                                pData.catCode = newCode;
                                isModified = true;
                            }
                            
                            let oldNameToCheck = existing ? (existing.name || '') : 'ไม่มีหมวดหมู่';
                            if (pData.category === oldNameToCheck || pData.category === 'ไม่ระบุ') {
                                pData.category = newName; 
                                isModified = true;
                            }
                            
                            if (isModified) {
                                batchStmts.push(updateProductStmt.bind(JSON.stringify(pData), pData.uid));
                            }
                        }
                    } catch(e) {}
                });
                
                if (batchStmts.length > 0) {
                    await env.DB.batch(batchStmts);
                }
            }

            return new Response(JSON.stringify({ success: true, message: `เปลี่ยนหมวดหมู่เป็น ${newName} (${newCode}) สำเร็จ` }), {
              status: 200, headers: { "Content-Type": "application/json", ...corsHeaders }
            });
            
        } catch (err) {
            console.error("Update Category Error:", err);
            return new Response(JSON.stringify({ success: false, message: err.message }), {
              status: 500,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
        }
      }

      // ==========================================
      // 21. API Endpoint: /splitProduct (แยกรายการสินค้า)
      // ==========================================
      if (request.method === "POST" && path === "/splitProduct") {
        const body = await request.json();
        const { updatedOriginal, newProducts } = body;

        let batchStmts = [];

        // 1. คำสั่งอัปเดตข้อมูลกล่องเดิม (รายการแรกที่พิมพ์)
        if (updatedOriginal && updatedOriginal.uid) {
            batchStmts.push(
                env.DB.prepare("UPDATE Products SET SKU = ?, JSON_Data = ?, UpdatedAt = CURRENT_TIMESTAMP WHERE UID = ?")
                .bind(updatedOriginal.sku, JSON.stringify(updatedOriginal), updatedOriginal.uid)
            );
        }

        // 2. คำสั่งเพิ่มสินค้ากล่องใหม่ (รายการที่ 2 เป็นต้นไป)
        if (newProducts && newProducts.length > 0) {
            const insertStmt = env.DB.prepare("INSERT INTO Products (UID, SKU, JSON_Data) VALUES (?, ?, ?)");
            newProducts.forEach(p => {
                batchStmts.push(insertStmt.bind(p.uid, p.sku, JSON.stringify(p)));
            });
        }

        // สั่งรันคำสั่งทั้งหมดพร้อมกันในครั้งเดียว
        if (batchStmts.length > 0) {
            await env.DB.batch(batchStmts);
        }

        return new Response(JSON.stringify({ success: true, message: "แยกรายการสินค้าสำเร็จ (ผ่าน CF)" }), {
          status: 200, headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      // ==========================================
      // 22. API Endpoint: /updateProductWechatGroups (อัปเดตกลุ่ม Wechat ให้สินค้าหลายรายการ)
      // ==========================================
      if (request.method === "POST" && path === "/updateProductWechatGroups") {
        const body = await request.json();
        const { skus, targetGroup } = body;

        if (!skus || skus.length === 0) {
          return new Response(JSON.stringify({ success: false, message: "ไม่มีรายการ SKU ให้แก้ไข" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // ดึงข้อมูลสินค้าที่ตรงกับ SKU
        const placeholders = skus.map(() => '?').join(',');
        const query = `SELECT * FROM Products WHERE SKU IN (${placeholders})`;
        const { results } = await env.DB.prepare(query).bind(...skus).all();

        if (results && results.length > 0) {
          let batchStmts = [];
          const updateStmt = env.DB.prepare("UPDATE Products SET JSON_Data = ?, UpdatedAt = CURRENT_TIMESTAMP WHERE UID = ?");

          results.forEach(row => {
            let pData = {};
            try { 
                pData = JSON.parse(row.JSON_Data); 
                pData.wechatGroup = targetGroup; // เปลี่ยนกลุ่ม
                batchStmts.push(updateStmt.bind(JSON.stringify(pData), pData.uid));
            } catch(e) {}
          });

          if (batchStmts.length > 0) {
            await env.DB.batch(batchStmts);
          }
        }

        return new Response(JSON.stringify({ success: true, message: `ย้าย ${skus.length} รายการไปยังกลุ่ม ${targetGroup} สำเร็จ` }), {
          status: 200, headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      // ==========================================
      // 23. API Endpoint: /fetchImagesToBase64 (ดาวน์โหลดภาพจาก URL เป็น Base64 สำหรับ Excel/PDF)
      // ==========================================
      if (request.method === "POST" && path === "/fetchImagesToBase64") {
        const body = await request.json();
        const urls = body.urls || [];
        let base64Map = {};

        await Promise.all(urls.map(async (imgUrl) => {
            try {
                const response = await fetch(imgUrl);
                if (response.ok) {
                    const arrayBuffer = await response.arrayBuffer();
                    const uint8Array = new Uint8Array(arrayBuffer);
                    
                    // แปลง Uint8Array เป็น Base64
                    let binaryString = '';
                    // ใช้ Chunk ในการแปลงเพื่อป้องกัน RangeError หากรูปมีขนาดใหญ่มาก
                    const chunkSize = 8192;
                    for (let i = 0; i < uint8Array.length; i += chunkSize) {
                        binaryString += String.fromCharCode.apply(null, uint8Array.slice(i, i + chunkSize));
                    }
                    const base64 = btoa(binaryString);
                    
                    // หา Extension
                    const contentType = response.headers.get('content-type') || '';
                    let ext = 'png';
                    if (contentType.includes('jpeg') || contentType.includes('jpg')) ext = 'jpeg';
                    else if (contentType.includes('webp')) ext = 'webp';

                    base64Map[imgUrl] = { base64: base64, ext: ext };
                }
            } catch (e) {
                console.error("Failed to fetch image:", imgUrl, e);
            }
        }));

        return new Response(JSON.stringify(base64Map), {
          status: 200, headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      // ==========================================
      // 24. API Endpoint: /updateShipmentCheckData (อัปเดตการตรวจรับเข้าโกดัง และพัสดุ)
      // ==========================================
      if (request.method === "POST" && path === "/updateShipmentCheckData") {
        const body = await request.json();
        
        const existing = await env.DB.prepare("SELECT * FROM Shipments WHERE Ship_ID = ?").bind(body.shipId).first();
        if (!existing) throw new Error("ไม่พบรายการจัดส่งนี้ในระบบ");

        let sData = JSON.parse(existing.JSON_Data);
        
        // อัปเดตข้อมูลที่ส่งมา
        if (body.updatedItems) sData.items = body.updatedItems;
        if (body.deliverySlips) sData.deliverySlipImages = body.deliverySlips;
        if (body.arrivalProds) sData.arrivalProductImages = body.arrivalProds;
        
        // 🌟 แก้ไขให้เช็คจาก !== undefined เพื่อให้บันทึกค่าว่างเปล่า (ลบรูปทิ้ง) ได้
        if (body.isDeliveryMatched !== undefined) sData.isDeliveryMatched = body.isDeliveryMatched;
        if (body.uploadT !== undefined) sData.deliveryUploadTime = body.uploadT;
        if (body.confirmT !== undefined) sData.deliveryConfirmTime = body.confirmT;
        if (body.arrUploadT !== undefined) sData.arrivalUploadTime = body.arrUploadT;
        if (body.actBox !== undefined && body.actBox !== null) sData.actualBoxCount = body.actBox;

        await env.DB.prepare("UPDATE Shipments SET JSON_Data = ?, UpdatedAt = CURRENT_TIMESTAMP WHERE Ship_ID = ?")
            .bind(JSON.stringify(sData), body.shipId)
            .run();

        return new Response(JSON.stringify({ message: "อัปเดตข้อมูลการตรวจสอบเรียบร้อยแล้ว", affectedGRs: [] }), {
            status: 200, headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      // ==========================================
      // 25. API Endpoint: /updateShipmentDoneStatus (Toggle สถานะ จัดการรายการ เสร็จสิ้น)
      // ==========================================
      if (request.method === "POST" && path === "/updateShipmentDoneStatus") {
        const { shipId, isDone, timeNow } = await request.json();
        
        const existing = await env.DB.prepare("SELECT * FROM Shipments WHERE Ship_ID = ?").bind(shipId).first();
        if (existing) {
            let sData = JSON.parse(existing.JSON_Data);
            sData.isDone = isDone;
            sData.doneTime = timeNow;
            
            await env.DB.prepare("UPDATE Shipments SET JSON_Data = ?, UpdatedAt = CURRENT_TIMESTAMP WHERE Ship_ID = ?")
                .bind(JSON.stringify(sData), shipId).run();
        }

        return new Response(JSON.stringify({ success: true }), {
          status: 200, headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      // ==========================================
      // 26. API Endpoint: /updateReceivingDownloadTime (อัปเดตเวลาการโหลด PDF ใบตรวจรับสินค้า)
      // ==========================================
      if (request.method === "POST" && path === "/updateReceivingDownloadTime") {
        const { shipId, timeNow } = await request.json();
        
        const existing = await env.DB.prepare("SELECT * FROM Shipments WHERE Ship_ID = ?").bind(shipId).first();
        if (existing) {
            let sData = JSON.parse(existing.JSON_Data);
            sData.lastReceivingDownload = timeNow;
            
            if (!sData.receivingDownloadTimes) sData.receivingDownloadTimes = [];
            sData.receivingDownloadTimes.push(timeNow);
            sData.isIrOutdated = false;
            
            await env.DB.prepare("UPDATE Shipments SET JSON_Data = ?, UpdatedAt = CURRENT_TIMESTAMP WHERE Ship_ID = ?")
                .bind(JSON.stringify(sData), shipId).run();
        }

        return new Response(JSON.stringify({ success: true }), {
          status: 200, headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      // ==========================================
      // 27. API Endpoint: /mergeShipmentItems (รวมรายการจัดส่ง)
      // ==========================================
      if (request.method === "POST" && path === "/mergeShipmentItems") {
        const { shipIds, targetPoId } = await request.json();

        // 1. ดึงข้อมูล Shipment ทั้งหมดที่เลือกรวม
        const placeholders = shipIds.map(() => '?').join(',');
        const query = `SELECT * FROM Shipments WHERE Ship_ID IN (${placeholders})`;
        const { results } = await env.DB.prepare(query).bind(...shipIds).all();

        if (!results || results.length === 0) throw new Error("ไม่พบข้อมูลเอกสารที่ต้องการรวม");

        let mergedItems = [];
        let origin = "", company = "";

        results.forEach(row => {
            let sData = JSON.parse(row.JSON_Data);
            if (sData.items) mergedItems.push(...sData.items);
            if (sData.origin && !origin) origin = sData.origin;
            if (sData.company && !company) company = sData.company;
        });

        // 2. สร้างเลขเอกสารใหม่ (อิงตาม PO หรือ Random)
        const d = new Date();
        const yyyy = d.getFullYear();
        const mm = String(d.getMonth() + 1).padStart(2, '0');
        const dd = String(d.getDate()).padStart(2, '0');
        const randomStr = Math.random().toString(36).substring(2, 6).toUpperCase();
        
        // รูปแบบนามสกุล -A ให้หน้าจอรู้ว่าเป็นใบรวม
        const newStId = `ST_MERGED_${yyyy}${mm}${dd}_${randomStr}-A`; 

        const newShipment = {
            shipId: newStId,
            shipDate: `${dd}/${mm}/${yyyy}`, 
            poIds: [targetPoId],
            items: mergedItems,
            isMergedGroup: true,
            origin: origin,
            company: company,
            isDone: false
        };

        // 3. เตรียมคำสั่ง Batch
        let batchStmts = [];
        const updateOld = env.DB.prepare("UPDATE Shipments SET JSON_Data = ?, UpdatedAt = CURRENT_TIMESTAMP WHERE Ship_ID = ?");
        
        // ทำเครื่องหมายว่าเอกสารเก่าถูกนำไปรวมแล้ว (isMerged)
        results.forEach(row => {
            let sData = JSON.parse(row.JSON_Data);
            sData.isMerged = true;
            sData.mergedTo = newStId;
            batchStmts.push(updateOld.bind(JSON.stringify(sData), sData.shipId));
        });

        // Insert เอกสารใหม่
        const insertNew = env.DB.prepare("INSERT INTO Shipments (Ship_ID, Ship_Date, JSON_Data) VALUES (?, ?, ?)");
        batchStmts.push(insertNew.bind(newStId, newShipment.shipDate, JSON.stringify(newShipment)));

        await env.DB.batch(batchStmts);

        return new Response(JSON.stringify({ newStId: newStId, message: "รวมรายการจัดส่งสำเร็จ" }), {
            status: 200, headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
      
      // ==========================================
      // 28. API Endpoint: /uploadPdfToR2 (อัปโหลด PDF ลง R2)
      // ==========================================
      if (request.method === "POST" && path === "/uploadPdfToR2") {
        const body = await request.json();
        const { fileName, pdfBase64 } = body; 
        
        // ใช้ URL โดเมน R2 เดิมของคุณ
        const R2_PUBLIC_URL = "https://pub-60abb993c7fc47f79ccea4b4c12dbde5.r2.dev/"; 

        try {
            // ตัด prefix ของ base64 ออก (เช่น "data:application/pdf;base64,")
            let base64Data = pdfBase64;
            if (base64Data.includes(',')) {
                base64Data = base64Data.split(',')[1];
            }

            // แปลง Base64 เป็น Binary
            const binaryString = atob(base64Data);
            const bytes = new Uint8Array(binaryString.length);
            for (let j = 0; j < binaryString.length; j++) {
                bytes[j] = binaryString.charCodeAt(j);
            }

            // ตั้งชื่อไฟล์ใหม่ให้ไม่ซ้ำกัน (เช่น PDF_123456_GR2024.pdf)
            const finalFileName = `PDF_${Date.now()}_${fileName}`;

            // อัปโหลดเข้า R2 Bucket
            await env.R2_BUCKET.put(finalFileName, bytes.buffer, {
                httpMetadata: { contentType: 'application/pdf' }
            });

            return new Response(JSON.stringify({ success: true, url: R2_PUBLIC_URL + finalFileName }), {
                status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
        } catch (error) {
            return new Response(JSON.stringify({ success: false, message: error.message }), {
                status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
        }
      }
      
      // ==========================================
      // 29. API Endpoint: /deletePurchaseOrder (ลบใบสั่งซื้อ 1 รายการ)
      // ==========================================
      if (request.method === "POST" && path === "/deletePurchaseOrder") {
        const body = await request.json();
        
        if (!body.poId) {
            return new Response(JSON.stringify({ success: false, message: "ไม่มีรหัส PO" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        await env.DB.prepare("DELETE FROM PurchaseOrders WHERE PO_ID = ?")
            .bind(body.poId)
            .run();

        return new Response(JSON.stringify({ success: true, message: `ลบเอกสาร ${body.poId} สำเร็จ` }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      // ==========================================
      // API Endpoint: /register (สมัครสมาชิกใหม่ พร้อมบันทึกลง Column ใหม่และ JSON_Data)
      // ==========================================
      if (request.method === "POST" && path === "/register") {
        try {
          const body = await request.json();
          
          // เช็คว่ามี Username หรือ Email ซ้ำไหม
          const existing = await env.DB.prepare("SELECT * FROM Users WHERE username = ? OR email = ?").bind(body.username, body.email).first();
          if (existing) {
            return new Response(JSON.stringify({ success: false, message: "Username หรือ Email นี้ถูกใช้งานแล้ว" }), {
              status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          // สร้าง ID แบบสุ่ม
          const userId = "MT" + Date.now().toString().substring(5) + Math.random().toString(36).substring(2, 6).toUpperCase();

          // 🌟 สร้างโครงสร้าง JSON ตั้งต้น เพื่อให้ระบบอ่านค่าต่างๆ ได้ไม่เกิด Error
          const initialJsonData = {
              user_id: userId,
              username: body.username || '',
              email: body.email || '',
              firstName: body.firstName || '',
              lastName: body.lastName || '',
              nickname: body.nickname || '',
              branch: body.branch || '',
              profilePic: body.profilePic || '',
              role: 'Subscriber',
              status: 'Pending',
              PageAccess: '1,2,3,4,5,8' // ค่าสิทธิ์เริ่มต้น
          };

          // 🌟 บันทึกข้อมูลลง Column หลัก และหยอด JSON ลงในช่อง JSON_Data ด้วย
          await env.DB.prepare(`
            INSERT INTO Users (user_id, username, password, email, role, status, FirstName, LastName, Nickname, Branch, ProfilePic, JSON_Data) 
            VALUES (?, ?, ?, ?, 'Subscriber', 'Pending', ?, ?, ?, ?, ?, ?)
          `).bind(
            userId, 
            body.username || '', 
            body.password || '', 
            body.email || '', 
            body.firstName || '', 
            body.lastName || '', 
            body.nickname || '', 
            body.branch || '', 
            body.profilePic || '',
            JSON.stringify(initialJsonData) // 🌟 เพิ่มข้อมูล JSON ลงฐานข้อมูล
          ).run();

          return new Response(JSON.stringify({ success: true, message: "ลงทะเบียนสำเร็จ รอการอนุมัติ" }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (error) {
          return new Response(JSON.stringify({ success: false, message: "DB Error: " + error.message }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      // ==========================================
      // API Endpoint: /login (เข้าสู่ระบบ)
      // ==========================================
      if (request.method === "POST" && path === "/login") {
        try {
          const body = await request.json();
          const user = await env.DB.prepare("SELECT * FROM Users WHERE username = ? AND password = ?").bind(body.username, body.password).first();
          
          if (user) {
            let parsedJson = {};
            try { if (user.JSON_Data) parsedJson = JSON.parse(user.JSON_Data); } catch(e) {}
            
            let userData = { ...parsedJson, ...user };
            
            // 🌟 สำคัญมาก: บังคับให้ระบบยึด Role จาก Column หลักของ Database เป็นอันดับแรกเสมอ
            if (user.role) userData.role = user.role;
            if (user.status) userData.status = user.status;
            if (user.FirstName) userData.FirstName = user.FirstName;
            if (user.LastName) userData.LastName = user.LastName;
            if (user.Nickname) userData.Nickname = user.Nickname;
            if (user.ProfilePic) userData.ProfilePic = user.ProfilePic;
            
            delete userData.password; // ลบรหัสผ่านทิ้งก่อนส่งกลับหน้าเว็บ
            
            return new Response(JSON.stringify({ success: true, user: userData }), {
              status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          } else {
            return new Response(JSON.stringify({ success: false, message: "Username หรือ Password ไม่ถูกต้อง" }), {
              status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }
        } catch (error) {
          return new Response(JSON.stringify({ success: false, message: "DB Error: " + error.message }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      // ==========================================
      // API Endpoint: /generate-otp-internal (สร้าง OTP ลับให้ Code.gs ไปส่ง Gmail)
      // ==========================================
      if (request.method === "POST" && path === "/generate-otp-internal") {
        const { email, secret } = await request.json();
        
        // 🌟 ป้องกันไม่ให้แฮกเกอร์ยิง API นี้ผ่านหน้าเว็บโดยตรง
        if (secret !== "MT_GMAIL_SECURE_99") {
            return new Response("Unauthorized", { status: 401, headers: corsHeaders });
        }

        const userRow = await env.DB.prepare("SELECT * FROM Users WHERE Email = ?").bind(email).first();
        
        if (!userRow) return new Response(JSON.stringify({ success: false, message: "ไม่พบอีเมลนี้ในระบบ" }), { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        if (userRow.Status !== 'Approved') return new Response(JSON.stringify({ success: false, message: "บัญชีของคุณกำลังรอการอนุมัติ" }), { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });

        // สร้าง OTP 5 หลัก
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let otp = '';
        for(let i=0; i<5; i++) otp += chars.charAt(Math.floor(Math.random() * chars.length));
        
        const expiry = new Date(new Date().getTime() + 5 * 60000).toISOString(); // 5 นาที

        await env.DB.prepare("UPDATE Users SET OTP_Code = ?, OTP_Expiry = ? WHERE Email = ?").bind(otp, expiry, email).run();

        // 🌟 ส่งรหัส OTP กลับไปให้ Code.gs (จะไม่ถูกส่งไปที่หน้าเว็บเพื่อความปลอดภัย)
        return new Response(JSON.stringify({ success: true, otp: otp }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ==========================================
      // [NEW] API Endpoint: /verify-otp (ยืนยัน OTP)
      // ==========================================
      if (request.method === "POST" && path === "/verify-otp") {
        const { email, otp } = await request.json();
        const userRow = await env.DB.prepare("SELECT * FROM Users WHERE Email = ? AND OTP_Code = ?").bind(email, otp.toUpperCase()).first();
        
        if (!userRow) return new Response(JSON.stringify({ success: false, message: "รหัส OTP ไม่ถูกต้อง" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        
        if (new Date(userRow.OTP_Expiry) < new Date()) {
            return new Response(JSON.stringify({ success: false, message: "รหัส OTP หมดอายุแล้ว" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        const userData = JSON.parse(userRow.JSON_Data);
        userData.role = userRow.Role;
        // 🌟 ดึงสิทธิ์จากคอลัมน์ PageAccess แนบกลับไปให้ Frontend
        if (userRow.PageAccess !== null && userRow.PageAccess !== undefined) userData.PageAccess = userRow.PageAccess;

        // เคลียร์ OTP
        await env.DB.prepare("UPDATE Users SET OTP_Code = NULL, OTP_Expiry = NULL WHERE Email = ?").bind(email).run();

        return new Response(JSON.stringify({ success: true, user: userData }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ==========================================
      // API Endpoint: /getUsers (ดึงข้อมูลพนักงาน แสดงผลหน้าจัดการสิทธิ์)
      // ==========================================
      if (request.method === "GET" && path === "/getUsers") {
        try {
          // 🌟 เอาคำสั่ง ORDER BY CreatedAt ออก เพื่อแก้ปัญหาคอลัมน์ไม่มีในฐานข้อมูล
          const res = await env.DB.prepare("SELECT * FROM Users").all();
          let usersList = [];
          
          if (res.results) {
            usersList = res.results.map(row => {
               let parsedJson = {};
               try { if (row.JSON_Data) parsedJson = JSON.parse(row.JSON_Data); } catch(e) {}
               
               return {
                 ...parsedJson,
                 ...row, 
               };
            });
          }

          return new Response(JSON.stringify({ success: true, users: usersList }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (error) {
          return new Response(JSON.stringify({ success: false, message: "DB Error: " + error.message }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      // ==========================================
      // API Endpoint: /updateUserRoleStatus (อัปเดตสิทธิ์พนักงาน)
      // ==========================================
      if (request.method === "POST" && path === "/updateUserRoleStatus") {
        try {
          const body = await request.json();
          
          // 1. ดึงข้อมูล User เดิมออกมาก่อน เพื่อเอา JSON_Data มาอัปเดต
          const user = await env.DB.prepare("SELECT * FROM Users WHERE user_id = ?").bind(body.user_id).first();
          if (!user) throw new Error("ไม่พบข้อมูลผู้ใช้งาน");

          let parsedJson = {};
          try { if (user.JSON_Data) parsedJson = JSON.parse(user.JSON_Data); } catch(e) {}
          
          let pageAccessStr = body.pageAccess.join(',');

          // 2. 🌟 อัปเดตค่าสิทธิ์ใหม่เข้าไปใน JSON_Data
          parsedJson.role = body.role;
          parsedJson.status = body.status;
          parsedJson.PageAccess = pageAccessStr;

          // 3. 🌟 บันทึกกลับลง Database (เพิ่มคอลัมน์ PageAccess เข้าไปในคำสั่ง SET)
          await env.DB.prepare(`
            UPDATE Users 
            SET role = ?, status = ?, PageAccess = ?, JSON_Data = ? 
            WHERE user_id = ?
          `).bind(
            body.role, 
            body.status, 
            pageAccessStr, 
            JSON.stringify(parsedJson), 
            body.user_id
          ).run();

          return new Response(JSON.stringify({ success: true, message: "อัปเดตสิทธิ์สำเร็จ" }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (error) {
          return new Response(JSON.stringify({ success: false, message: "DB Error: " + error.message }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      // ==========================================
      // API Endpoint: /update-profile (อัปเดตข้อมูลส่วนตัวและรหัสผ่าน)
      // ==========================================
      if (request.method === "POST" && path === "/update-profile") {
        try {
          const body = await request.json();
          
          // 1. ตรวจสอบว่าส่ง user_id มาหรือไม่
          if (!body.user_id) {
             return new Response(JSON.stringify({ success: false, message: "ไม่พบ User ID" }), {
                status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
             });
          }

          // 2. ถ้ามีการขอเปลี่ยนรหัสผ่าน ต้องเช็ครหัสผ่านเก่าก่อน
          let sqlQuery = `UPDATE Users SET FirstName = ?, LastName = ?, Nickname = ?, Branch = ?, ProfilePic = ?`;
          let params = [
             body.firstName || '', 
             body.lastName || '', 
             body.nickname || '', 
             body.branch || '', 
             body.profilePic || ''
          ];

          if (body.newPassword && body.newPassword !== '') {
             // เช็ครหัสผ่านเก่า
             const user = await env.DB.prepare("SELECT password FROM Users WHERE user_id = ?").bind(body.user_id).first();
             if (!user || user.password !== body.oldPassword) {
                return new Response(JSON.stringify({ success: false, message: "รหัสผ่านเดิมไม่ถูกต้อง" }), {
                   status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
                });
             }
             // ถ้ารหัสผ่านเก่าถูก ให้เพิ่มคำสั่งอัปเดตรหัสผ่านใหม่
             sqlQuery += `, password = ?`;
             params.push(body.newPassword);
          }

          // 3. ปิดท้ายคำสั่ง SQL ด้วยเงื่อนไข WHERE
          sqlQuery += ` WHERE user_id = ?`;
          params.push(body.user_id);

          // 4. สั่งรัน Database
          await env.DB.prepare(sqlQuery).bind(...params).run();

          return new Response(JSON.stringify({ success: true, message: "อัปเดตโปรไฟล์สำเร็จ" }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });

        } catch (error) {
          // 🌟 ถ้าเกิด Error (เช่น ชื่อคอลัมน์ผิด) ให้ส่งข้อความกลับไปโชว์ที่หน้าเว็บแบบสวยๆ
          return new Response(JSON.stringify({ success: false, message: "DB Error: " + error.message }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }
      
      // ==========================================
      // [NEW] API Endpoint: /getLogs (ดึงข้อมูล Log ทั้งหมด สำหรับ Admin)
      // ==========================================
      if (request.method === "GET" && path === "/getLogs") {
        const res = await env.DB.prepare("SELECT * FROM Logs ORDER BY DateString DESC LIMIT 30").all();
        let allLogs = [];
        if (res.results) {
          res.results.forEach(row => {
            try {
              let logArr = JSON.parse(row.LogArray_JSON);
              allLogs = allLogs.concat(logArr);
            } catch(e) {}
          });
        }
        // เรียงลำดับจากใหม่สุดไปเก่าสุด
        allLogs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        allLogs.reverse();
        
        return new Response(JSON.stringify({ success: true, logs: allLogs }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      // ==========================================
      // [NEW] API Endpoint: /saveVrBills (บันทึกข้อมูลบิลจาก Sheet1)
      // ==========================================
      if (request.method === "POST" && path === "/saveVrBills") {
        const body = await request.json();
        let bills = body.bills || [];
        
        if (bills.length > 0) {
            const stmts = bills.map(b => {
                let jsonStr = JSON.stringify(b);
                return env.DB.prepare(`
                    INSERT INTO VrBills (OrderNo, DateStr, BillJSON, Timestamp) 
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP) 
                    ON CONFLICT(OrderNo) DO UPDATE SET BillJSON=excluded.BillJSON, Timestamp=CURRENT_TIMESTAMP
                `).bind(b.orderNo, b.date, jsonStr);
            });
            await env.DB.batch(stmts);
        }

        return new Response(JSON.stringify({ success: true, message: "บันทึกข้อมูลบิลสำเร็จ" }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // [NEW] API Endpoint: /getVrBills (ดึงข้อมูลบิล)
      // ==========================================
      if (request.method === "GET" && path === "/getVrBills") {
        // ดึง 500 บิลล่าสุด
        const res = await env.DB.prepare("SELECT * FROM VrBills ORDER BY Timestamp DESC LIMIT 10000").all();
        let bills = [];
        if (res.results) {
            bills = res.results.map(row => JSON.parse(row.BillJSON));
        }
        return new Response(JSON.stringify({ success: true, bills: bills }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      // ==========================================
      // API Endpoint: /saveCcRecord (บันทึกข้อมูลและอัปเดตบัตรเครดิต)
      // ==========================================
      if (request.method === "POST" && path === "/saveCcRecord") {
        const body = await request.json();
        await env.DB.prepare(`
          INSERT INTO CcRecords (ID, JSON_Data, CreatedAt) 
          VALUES (?, ?, CURRENT_TIMESTAMP) 
          ON CONFLICT(ID) DO UPDATE SET JSON_Data=excluded.JSON_Data, UpdatedAt=CURRENT_TIMESTAMP
        `).bind(body.id, JSON.stringify(body)).run();

        return new Response(JSON.stringify({ success: true }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // ==========================================
      // API Endpoint: /getCcRecords (ดึงข้อมูลบัตรเครดิตทั้งหมด)
      // ==========================================
      if (request.method === "GET" && path === "/getCcRecords") {
        const res = await env.DB.prepare("SELECT * FROM CcRecords ORDER BY CreatedAt DESC LIMIT 500").all();
        let records = [];
        if (res.results) {
          records = res.results.map(row => JSON.parse(row.JSON_Data));
        }
        return new Response(JSON.stringify({ success: true, records: records }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      // 🔴🔴 โค้ดดักจับ 404 (บรรทัดนี้ต้องอยู่ล่างสุดเสมอ ห้ามมี if API อะไรมาต่อท้าย) 🔴🔴
      return new Response(JSON.stringify({ error: "API Endpoint not found", method: request.method, path: path }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });

    } catch (error) {
      return new Response(JSON.stringify({ error: "Backend Error: " + error.message }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

  } // <-- สิ้นสุดฟังก์ชัน fetch
}; // <-- สิ้นสุด export default