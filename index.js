import express from "express";
import axios from "axios";
import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config();

const app = express();

// ===== Verify middleware for raw body (for signature check) =====
function rawBodySaver(req, res, buf) {
  req.rawBody = buf;
}

// ===== Env Vars =====
const PAGE_ACCESS_TOKEN = process.env.PAGE_ACCESS_TOKEN; // From your FB App/Page connection
const VERIFY_TOKEN = process.env.VERIFY_TOKEN; // Arbitrary string you set for webhook verification
const APP_SECRET = process.env.APP_SECRET; // FB App secret (optional but recommended for signature verify)
const PORT = process.env.PORT || 3000;

if (!PAGE_ACCESS_TOKEN || !VERIFY_TOKEN) {
  console.error("Missing env vars: PAGE_ACCESS_TOKEN and/or VERIFY_TOKEN.");
}

// ===== Webhook verification (GET) =====
app.get("/webhook", (req, res) => {
    console.log("webhook working");
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  } else {
    return res.sendStatus(403);
  }
});


// ------------------ Helpers ------------------
async function getIGUserId() {
  // Fetch Instagram Business Account ID linked to the Page token
  // 1) Get page id from token (me)
  // 2) From page: fields=connected_instagram_account OR instagram_business_account
  // Different setups expose either one; we’ll try both.

  // Get Page ID
  const me = await axios.get(
    `https://graph.facebook.com/v21.0/me?fields=id&access_token=${PAGE_ACCESS_TOKEN}`
  );
  const PAGE_ID = me.data.id;

  // Try to resolve IG business user via page fields
  const pageResp = await axios.get(
    `https://graph.facebook.com/v21.0/${PAGE_ID}?fields=connected_instagram_account,instagram_business_account&access_token=${PAGE_ACCESS_TOKEN}`
  );

  const igUserId =
    pageResp.data?.connected_instagram_account?.id ||
    pageResp.data?.instagram_business_account?.id;

  if (!igUserId) {
    throw new Error(
      "Could not resolve IG Business User ID. Ensure IG account is connected to the FB Page and permissions are granted."
    );
  }
  return igUserId;
}

// Safe axios GET with bearer token and passthrough of query params
async function graphGet(url, params = {}) {
  const { data } = await axios.get(url, {
    params: { ...params, access_token: PAGE_ACCESS_TOKEN },
  });
  return data;
}

// ------------------ Routes ------------------

/**
 * GET /ig/conversations
 * Query params:
 *  - limit (optional, default 25)
 *  - before / after (optional; Graph pagination cursors)
 */
app.get("/ig/conversations", async (req, res) => {
  try {
    const igUserId = await getIGUserId();
    const { limit = 25, before, after } = req.query;

    const params = { limit };
    if (before) params.before = before;
    if (after) params.after = after;

    // List IG conversations for the business user
    // Fields you can request: id, participants, updated_time, folder, etc.
    const data = await graphGet(
      `https://graph.facebook.com/v21.0/${igUserId}/conversations`,
      {
        ...params,
        // keep fields minimal and safe
        fields:
          "id,updated_time,participants.limit(50){id,username},link",
      }
    );

    res.json({
      success: true,
      data: data.data || [],
      paging: data.paging || null,
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      error: stringifyGraphError(err),
    });
  }
});

// ===== Use JSON parser AFTER webhook GET =====
app.use(express.json({ verify: rawBodySaver }));

// ===== Verify X-Hub-Signature (optional but recommended) =====
function verifyMetaSignature(req) {
  try {
    const signature = req.headers["x-hub-signature-256"];
    if (!signature || !APP_SECRET) return true; // Skip if not configured
    const expected =
      "sha256=" +
      crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );
  } catch (e) {
    return false;
  }
}

// ===== Webhook receiver (POST) =====
app.post("/webhook", async (req, res) => {
    console.log(req,'assdas');
  if (!verifyMetaSignature(req)) {
    return res.sendStatus(403);
  }

  const body = req.body;
  console.log("incoming webhook",body);
  // Body contains entry[...].messaging[] events, including IG DMs if configured
  if (body.object !== "instagram") {
    // For some setups, object can be 'page' but messaging_product is 'instagram'. We'll just proceed generically.
  }

  try {
    if (body.entry) {
      for (const entry of body.entry) {
        const changes = entry.messaging || entry.standby || [];
        for (const event of changes) {
          // IG PSID (user id for messaging) lives in sender.id
          const senderId = event?.sender?.id;
          const messageText = event?.message?.text;
          const isMessage = Boolean(event?.message);

          if (isMessage && senderId) {
            // Example auto-reply (only for demo). In production, add your logic & respect 24h window.
            const replyText = `Thanks for messaging us! You said: "${
              messageText || "(no text)"
            }"`;
            const result = await tryReplyInstagram(senderId, replyText);
            // Important: result.ok === true DOES NOT imply the user follows you.
            console.log("Reply attempt:", result);
          }
        }
      }
    }
  } catch (err) {
    console.error("Webhook processing error:", err?.response?.data || err);
  }

  res.sendStatus(200);
});

// ===== Utility: send a reply to an IG user (PSID) =====
async function tryReplyInstagram(igPsid, text) {
  try {
    const url = `https://graph.facebook.com/v21.0/me/messages`;
    const payload = {
      messaging_product: "instagram",
      recipient: { id: igPsid },
      message: { text },
    };

    const { data } = await axios.post(url, payload, {
      headers: { Authorization: `Bearer ${PAGE_ACCESS_TOKEN}` },
    });

    // Success means: message accepted for delivery within policy rules
    return { ok: true, data };
  } catch (error) {
    const errData = error?.response?.data || {};

    // Common causes of failure (NOT related to follow status):
    // - 24-hour window closed (policy restriction)
    // - Missing permissions or wrong app mode (development vs live)
    // - Invalid Page token / IG account not connected
    // - Rate limits

    // You cannot infer follow status from any of these.
    return {
      ok: false,
      error: {
        status: error?.response?.status,
        code: errData?.error?.code,
        subcode: errData?.error?.error_subcode,
        message: errData?.error?.message,
        type: errData?.error?.type,
      },
    };
  }
}

// ===== Healthcheck =====
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});

/*
    Setup checklist:
    1) Create FB App -> add "Instagram Graph API" and "Messenger" products.
    2) Convert your IG to a Professional account and connect it to a FB Page.
    3) In App -> Messenger settings -> Instagram -> Connect IG account, enable "Manage and access messages".
    4) Generate a Page Access Token (with pages_messaging, instagram_basic, instagram_manage_messages, pages_manage_metadata, etc.).
    5) Set env vars: PAGE_ACCESS_TOKEN, VERIFY_TOKEN, APP_SECRET.
    6) Expose your server via HTTPS (ngrok) and set the Webhook callback URL + verify token in App dashboard.
    7) Subscribe to the right fields (messages, message_reads, messaging_postbacks) for Instagram.
    8) Test by sending a DM from a separate IG account to your business IG.

    Important: Success of sending a reply only indicates policy conditions are met (e.g., within 24h window), NOT that the user follows you.
    */
