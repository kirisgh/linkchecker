const express = require("express");
const cors = require("cors");
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));
const tls = require("tls");
require("dotenv").config();

const chromium = require("chrome-aws-lambda");
const puppeteer = require("puppeteer-core");

const app = express();
const PORT = 3000;
const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

app.use(cors());
app.use(express.json());

// ✅ Test Route
app.get("/", (req, res) => {
  res.send("🚀 Server is running successfully!");
});

// ✅ Start Server
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});

// ✅ Run Puppeteer
(async () => {
    const browser = await puppeteer.launch({
        args: chromium.args,
        executablePath: await chromium.executablePath,
        headless: chromium.headless
    });

    const page = await browser.newPage();
    await page.goto("https://example.com");

    console.log(await page.title());
    await browser.close();
})();


runPuppeteer();

// ✅ Main API Endpoint
app.get("/check-link", async (req, res) => {
  let url = req.query.url;
  if (!url) return res.status(400).json({ error: "No URL provided" });

  if (!url.startsWith("http")) url = "https://" + url;

  try {
    console.log(`🔍 Checking: ${url}`);
    let warnings = [];

    const sslRisk = await checkSSL(url);
    if (sslRisk) warnings.push({ type: "SSL Issue", reason: sslRisk });

    const threatType = await checkForMalware(url);
    if (threatType) warnings.push({ type: "Unsafe", reason: threatType });

    const httpRisk = await checkHttpStatus(url);
    if (httpRisk) warnings.push({ type: "Broken Link", reason: httpRisk });

    console.log("Warnings for:", url, warnings);

    return res.json({
      status: warnings.length > 0 ? "warning" : "working",
      warnings,
    });
  } catch (error) {
    console.error(`❌ Error fetching URL: ${url}`, error.message);
    return res.json({ status: "broken", error: error.message });
  }
});

// ✅ SSL Certificate Check
async function checkSSL(url) {
  return new Promise((resolve) => {
    try {
      const { hostname } = new URL(url);
      const options = { host: hostname, port: 443, rejectUnauthorized: false };

      const socket = tls.connect(options, () => {
        const cert = socket.getPeerCertificate();

        if (!cert || Object.keys(cert).length === 0) {
          resolve("No valid SSL certificate.");
        } else if (cert.valid_to && new Date(cert.valid_to) < new Date()) {
          resolve("Expired SSL certificate.");
        } else if (!cert.issuer || !cert.issuer.O) {
          resolve("Self-signed or untrusted SSL certificate.");
        } else {
          resolve(null);
        }

        socket.end();
      });

      socket.on("error", () => resolve("Fake or misconfigured SSL certificate."));
    } catch (error) {
      resolve("SSL check failed.");
    }
  });
}

// ✅ Google Safe Browsing Malware Check
async function checkForMalware(url) {
  const apiURL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`;
  const body = {
    client: { clientId: "link-checker", clientVersion: "1.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  try {
    const response = await fetch(apiURL, {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    });

    const data = await response.json();
    return data.matches && data.matches.length > 0 ? data.matches[0].threatType : null;
  } catch (error) {
    console.error("🚨 Safe Browsing API Error:", error);
    return null;
  }
}

// ✅ HTTP Status Check
async function checkHttpStatus(url) {
  try {
    const response = await fetch(url, { method: "HEAD" });
    return !response.ok ? `HTTP error: ${response.status}` : null;
  } catch (error) {
    return "Site is unreachable";
  }
}

// ✅ Test Puppeteer on Deployment
async function testPuppeteer() {
    let browser = null;
    try {
        browser = await puppeteer.launch({
            args: chromium.args,
            executablePath: await chromium.executablePath || puppeteer.executablePath(),
            headless: chromium.headless,
        });

        const page = await browser.newPage();
        await page.goto("https://www.google.com", { waitUntil: "load", timeout: 10000 });
        console.log("✅ Puppeteer is working!");
    } catch (error) {
        console.error("❌ Puppeteer test failed:", error.message);
    } finally {
        if (browser) await browser.close();
    }
}

testPuppeteer();
