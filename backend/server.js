require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { spawn } = require('child_process');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();

// ==========================================
// DEPLOYING TUNED SECURITY SHIELDS
// ==========================================

// 1. Enterprise Security Headers (Tuned for functional UI)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            // Allow Supabase CDN and inline scripts
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            // Explicitly allow onclick="" attributes on your buttons
            scriptSrcAttr: ["'unsafe-inline'"], 
            // Allow Supabase Database Connection
            connectSrc: ["'self'", "https://sgimhtcmtyntufnytqaf.supabase.co"],
            // Allow Google Fonts
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
            imgSrc: [
                "'self'", 
                "data:", 
                "blob:", 
                "https://github.com", 
                "https://avatars.githubusercontent.com"
            ],
        },
    },
    // Prevent blocking of standard cross-origin resource sharing
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
}));

// 2. Cloud-Ready CORS Policy
// Using '*' ensures your Netlify frontend won't get blocked by the Render backend.
app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// 3. Custom WAF Middleware (Patches .env and .git exposure)
app.use((req, res, next) => {
    const url = req.url.toLowerCase();
    if (url.includes('.env') || url.includes('.git')) {
        console.warn(`[WAF] Blocked malicious path traversal attempt: ${req.ip} -> ${url}`);
        return res.status(403).send('Forbidden: Access Denied by Sentinel-X WAF');
    }
    next();
});

// Remove Server Fingerprint
app.disable('x-powered-by');

// ==========================================
// CORE SERVER LOGIC
// ==========================================

app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Initialize Supabase Client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Master Scan Endpoint
app.post('/api/scan', async (req, res) => {
    const targetUrl = req.body.target;
    if (!targetUrl) return res.status(400).json({ error: 'Target URL is required.' });

    console.log(`[*] Initiating Sentinel-X Agent -> ${targetUrl}`);
    
    const agentPath = path.join(__dirname, '../agent/agent.py');
    const pythonProcess = spawn('python3', [agentPath, targetUrl]);

    let dataString = '';

    pythonProcess.stdout.on('data', (data) => { dataString += data.toString(); });
    pythonProcess.stderr.on('data', (data) => { console.error(`[AGENT ERROR]: ${data}`); });

    pythonProcess.on('close', async (code) => {
        if (code !== 0) return res.status(500).json({ error: 'Agent execution failed.' });

        try {
            const parsedData = JSON.parse(dataString);
            
            // Check if Python returned an error (like "target unreachable")
            if (parsedData.error || !parsedData.findings) {
                return res.json({ error: parsedData.error || "Agent returned invalid telemetry.", data: parsedData });
            }

            // Now it is 100% safe to filter because we know 'findings' exists
            const logsToInsert = parsedData.findings
                .filter(f => f.status === 'Vulnerable' || f.status === 'CRITICAL' || f.status === 'Warning')
                .map(finding => ({
                    target_endpoint: targetUrl,
                    vulnerability_type: finding.vulnerability_type,
                    status: finding.status,
                    remediation_code: finding.remediation_code_generated || "None required."
                }));

            if (logsToInsert.length > 0) {
                const { error } = await supabase.from('scan_logs').insert(logsToInsert);
                if (error) throw error;
            }

            res.json({ success: true, data: parsedData });
        } catch (err) {
            console.error('[!] Error:', err);
            res.status(500).json({ error: 'Failed to process telemetry.' });
        }
    });
});

// ==========================================
// CYPHERVAULT AI ENDPOINT (GEMINI INTEGRATION)
// ==========================================

// Diagnostic Check: Validate API Key on Boot
if (!process.env.GEMINI_API_KEY) {
    console.error("[!] FATAL WARNING: GEMINI_API_KEY is missing from .env file!");
} else {
    console.log("[*] Gemini AI Core: Authenticated & Ready.");
}

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

app.post('/api/chat', async (req, res) => {
    const userMessage = req.body.message;
    
    // Safety check before calling the API
    if (!process.env.GEMINI_API_KEY) {
        return res.status(500).json({ reply: "SYSTEM ERROR: API Key missing in backend configuration." });
    }

    try {
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
        
        const systemInstruction = `
            You are CypherVault AI Copilot, an advanced, intellectual DevSecOps assistant embedded in the Sentinel-X platform.
            Your persona is brilliant, highly analytical, but warm and conversational—like an expert cyber-tactician mentoring a colleague. 
            
            Key Directives:
            - If the user says hello or asks about your day, greet them warmly.
            - If asked "who created you", explain that you were developed by the elite Sentinel-X engineering team.
            - If asked about the purpose of Sentinel-X, explain that it is a next-generation automated vulnerability reconnaissance and DevSecOps platform designed to harden infrastructure.
            - If the user provides a URL or asks a technical question, provide a deep, educational security breakdown.
            - Never use cold, robotic rejections like "Target undefined." Instead, politely ask for clarification or guide them on how to use the scanner.
            - Format your responses cleanly using short paragraphs or bullet points. Do not use markdown headers (like # or ##).
        `;

        const prompt = `${systemInstruction}\n\nOperator Query: ${userMessage}`;
        
        const result = await model.generateContent(prompt);
        const aiReply = result.response.text();
        
        // Convert basic markdown bolding to HTML
        const formattedReply = aiReply.replace(/\*\*(.*?)\*\*/g, '<b style="color: #6366F1;">$1</b>');

        res.json({ reply: formattedReply });
    } catch (err) {
        console.error("\n[!] GEMINI API ERROR DETAILS:");
        console.error(err);
        res.status(500).json({ reply: `CRITICAL: AI Core Failure. Backend Log: ${err.message}` });
    }
});

const PORT = process.env.PORT || 8080;
// CRITICAL FIX: Bound to '0.0.0.0' so Render can accurately route traffic to this container
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[*] Sentinel-X C2 Online on port ${PORT}`);
    console.log(`[*] Security Shields: TUNED & ACTIVE`);
});