const express = require("express");
const cors = require("cors");
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));
const tls = require("tls");
const https = require("https");
const chromium = require("chrome-aws-lambda");
const puppeteer = require("puppeteer");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyBkg5kLoZKK7_bZO - bvzjb8jUWkj_58XWA";

app.use(cors());
app.use(express.json());

// ✅ Test Route
app.get("/", (req, res) => {
  res.send("🚀 Server is running successfully!");
});

// ✅ Start Server & Handle Port Conflicts
function startServer(port) {
    const server = app.listen(port, () => {
        console.log(`✅ Server running on port ${server.address().port}`);
    }).on("error", (err) => {
        if (err.code === "EADDRINUSE") {
            console.warn(`⚠️ Port ${port} in use. Trying a different port...`);
            startServer(0); // Try a new port
        } else {
            console.error(`❌ Server error: ${err.message}`);
        }
    });
}

startServer(PORT);

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

        const adRisk = await checkForAds(url);
        if (adRisk) warnings.push({ type: "Ad-Heavy", reason: adRisk });

        const redirectRisk = await checkForRedirects(url);
        if (redirectRisk) warnings.push({ type: "Redirect-Heavy", reason: redirectRisk });

        const httpRisk = await checkHttpStatus(url);
        if (httpRisk) warnings.push({ type: "Broken Link", reason: httpRisk });

        console.log("Warnings for:", url, warnings);

        return res.json({
            status: warnings.length > 0 ? "warning" : "working",
            warnings
        });
    } catch (error) {
        console.error(`❌ Error fetching URL: ${url}`, error.message);
        return res.json({ status: "broken", error: error.message });
    }
});

// ✅ Improved SSL Certificate Check
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
                    resolve(null); // SSL is valid
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
        const response = await fetch(apiURL, { method: "POST", body: JSON.stringify(body), headers: { "Content-Type": "application/json" } });
        const data = await response.json();
        return data.matches && data.matches.length > 0 ? data.matches[0].threatType : null;
    } catch (error) {
        console.error("🚨 Safe Browsing API Error:", error);
        return null;
    }
}

// ✅ Puppeteer Ad Detection
async function checkForAds(url) {
    try {
        const browser = await puppeteer.launch({
            headless: "new",
            args: ["--no-sandbox", "--disable-setuid-sandbox"],
            executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || "/opt/render/.cache/puppeteer/chrome/linux-133.0.6943.126/chrome-linux64/chrome"
        });

        const page = await browser.newPage();
        await page.goto(url, { waitUntil: "load", timeout: 30000 });

        const ads = await page.evaluate(() =>
            document.querySelectorAll("iframe, div[id*='ad'], [class*='ad']").length
        );

        await browser.close();
        return ads > 3 ? "📢 Excessive ads/pop-ups detected" : null;
    } catch (error) {
        console.error("🚨 Ad detection failed:", error.message);
        return null;
    }
}

// ✅ Redirect Detection
async function checkForRedirects(url) {
    try {
        const browser = await puppeteer.launch({ headless: "new" });
        const page = await browser.newPage();
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 10000 });

        await page.waitForNavigation({ timeout: 30000 }).catch(() => { });
        const finalUrl = page.url();
        await browser.close();
        return finalUrl !== url ? `Redirects to ${finalUrl}` : null;
    } catch (error) {
        console.error("Redirect detection failed:", error);
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
    try {
        const browser = await puppeteer.launch({ headless: "new" });
        const page = await browser.newPage();
        await page.goto("https://www.google.com", { waitUntil: "load", timeout: 10000 });
        console.log("✅ Puppeteer is working!");
        await browser.close();
    } catch (error) {
        console.error("❌ Puppeteer test failed:", error.message);
    }
}

testPuppeteer();
