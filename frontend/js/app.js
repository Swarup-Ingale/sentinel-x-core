document.addEventListener('DOMContentLoaded', () => {

    // 1. Smooth Page Transitions & BF-Cache Fix
    const links = document.querySelectorAll('a[href]');
    links.forEach(link => {
        link.addEventListener('click', (e) => {
            const target = link.getAttribute('href');
            if (target && target.endsWith('.html')) {
                e.preventDefault();
                document.body.classList.add('fade-out');
                setTimeout(() => window.location.href = target, 300); 
            }
        });
    });

    window.addEventListener('pageshow', (event) => {
        if (event.persisted || document.body.classList.contains('fade-out')) {
            document.body.classList.remove('fade-out');
        }
    });

    // 2. Mouse Tracking Glow for Cards
    document.querySelectorAll('.card.interactive').forEach(card => {
        card.addEventListener('mousemove', e => {
            const rect = card.getBoundingClientRect();
            card.style.setProperty('--mouse-x', `${e.clientX - rect.left}px`);
            card.style.setProperty('--mouse-y', `${e.clientY - rect.top}px`);
        });
    });

    // 3. Terminal Emulator (dashboard.html only)
    const termInput = document.getElementById('terminal-input');
    const termHistory = document.getElementById('terminal-history');
    const termWindow = document.getElementById('terminal-window');

    if (termInput && termHistory) {
        let cmdHistory = [];
        let historyIndex = -1;

        termWindow.addEventListener('click', () => termInput.focus());

        function printLog(html) {
            const div = document.createElement('div');
            div.innerHTML = html;
            termHistory.appendChild(div);
            termWindow.scrollTop = termWindow.scrollHeight;
        }

        // Arrow Key Command History
        termInput.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (cmdHistory.length > 0 && historyIndex < cmdHistory.length - 1) {
                    historyIndex++;
                    termInput.value = cmdHistory[cmdHistory.length - 1 - historyIndex];
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (historyIndex > 0) {
                    historyIndex--;
                    termInput.value = cmdHistory[cmdHistory.length - 1 - historyIndex];
                } else if (historyIndex === 0) {
                    historyIndex = -1;
                    termInput.value = '';
                }
            }
        });

        // Command Execution
        termInput.addEventListener('keypress', async (e) => {
            if (e.key === 'Enter') {
                const rawCmd = termInput.value.trim();
                const cmdArgs = rawCmd.split(' ');
                const cmd = cmdArgs[0].toLowerCase();
                
                if (rawCmd) {
                    cmdHistory.push(rawCmd);
                    historyIndex = -1;
                }
                termInput.value = '';
                printLog(`<div><span class="terminal-prompt">root@sentinel-x:~#</span> <span class="t-cmd">${rawCmd}</span></div>`);

                if (!cmd) return;

                switch(cmd) {
                    case 'help': printLog(`<div class="t-sys">Commands: clear, whoami, date, ls, ping, uptime, sysinfo, echo, <span class="t-info">scan</span></div>`); break;
                    case 'clear': termHistory.innerHTML = ''; break;
                    case 'whoami': printLog(`<div class="t-cmd">root (super-user)</div>`); break;
                    case 'date': printLog(`<div class="t-sys">${new Date().toString()}</div>`); break;
                    case 'ls': printLog(`<div class="t-info">agent.py payloads/ logs/ config.json server.js</div>`); break;
                    case 'scan': 
                        if (cmdArgs[1] === '--target' && cmdArgs[2]) await executeScan(cmdArgs[2]);
                        else printLog(`<div class="t-err">Usage: scan --target &lt;url&gt;</div>`);
                        break;
                    default: printLog(`<div class="t-err">bash: ${cmd}: command not found.</div>`);
                }
            }
        });

        // The Upgraded Exploit Logic tied to the terminal
        async function executeScan(target) {
            printLog(`<div class="t-info">[*] Deploying Sentinel-X Agent to target: ${target}</div>`);
            
            const loaderId = 'loader-' + Date.now();
            printLog(`<div id="${loaderId}" class="t-sys">Analyzing target infrastructure and payload reflection...</div>`);
            
            try {
                const response = await fetch('https://sentinel-x-api.onrender.com/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target })
                });
                
                if(document.getElementById(loaderId)) document.getElementById(loaderId).remove();
                const result = await response.json();
                
                if (result.error) {
                    printLog(`<div class="t-err">[!] SYSTEM FAILURE: ${result.error}</div>`);
                    return;
                }

                if (!result.data.findings || result.data.findings.length === 0) {
                    printLog(`<div class="t-success">[-] Scan complete. Target appears secure.</div>`);
                    return;
                }

                // Render the new detailed terminal findings
                result.data.findings.forEach(finding => {
                    if (['CRITICAL', 'Vulnerable', 'Warning'].includes(finding.status)) {
                        
                        // Determine color based on threat level
                        let threatColor = '#FFBD2E'; // Yellow for Warning
                        if (finding.status === 'Vulnerable') threatColor = '#F2555A'; // Red
                        if (finding.status === 'CRITICAL') threatColor = '#FF2A2A'; // Deep Red
                        
                        const safeVuln = finding.vulnerable_code.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>');
                        const safePatch = finding.remediation_code_generated.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>');
                        
                        printLog(`
                            <div style="margin-top: 24px; border-top: 1px dashed var(--border-dim); padding-top: 12px;">
                                <div style="font-weight: bold; font-size: 1.05rem; color: ${threatColor};">[!] ${finding.status.toUpperCase()}: ${finding.vulnerability_type}</div>
                                <div class="t-sys" style="margin-top: 8px;"><b>Exploit Vector:</b> ${finding.explanation}</div>
                                
                                <div class="t-sys" style="margin-top: 12px; color: ${threatColor};">[-] IDENTIFIED VULNERABLE LOGIC:</div>
                                <div class="t-patch" style="border-left: 3px solid ${threatColor}; color: #e0e0e0;">${safeVuln}</div>
                                
                                <div class="t-info" style="margin-top: 12px; color: #4CC38A;">[+] ZERO-DAY REMEDIATION GENERATED:</div>
                                <div class="t-patch" style="border-left: 3px solid #4CC38A; color: #e0e0e0;">${safePatch}</div>
                            </div>
                        `);
                    } else if (finding.status === "Secure") {
                        // Print the secure findings as a quiet success list
                        printLog(`<div class="t-success" style="margin-top: 8px;">[-] TARGET HARDENED: ${finding.vulnerability_type}</div>`);
                    }
                });
                
                printLog(`<div class="t-sys" style="margin-top: 16px;">[*] Execution finished. Telemetry synced to central database.</div>`);

            } catch (err) {
                if(document.getElementById(loaderId)) document.getElementById(loaderId).remove();
                printLog(`<div class="t-err">[!] FATAL: Connection to C2 Server severed. Ensure backend is active.</div>`);
            }
        }
    }

    // ==========================================
    // CYPHERVAULT AI ASSISTANT LOGIC
    // ==========================================
    const aiTrigger = document.getElementById('ai-trigger-btn');
    const aiWidget = document.getElementById('ai-chat-widget');
    const closeChat = document.getElementById('close-chat');
    const chatInput = document.getElementById('chat-input');
    const sendChat = document.getElementById('send-chat');
    const chatWindow = document.getElementById('chat-window');

    if (aiTrigger && aiWidget) {
        // Toggle Widget
        aiTrigger.addEventListener('click', () => aiWidget.classList.remove('hidden'));
        closeChat.addEventListener('click', () => aiWidget.classList.add('hidden'));

        // Handle Sending Messages
        const handleSend = async () => {
            const text = chatInput.value.trim();
            if (!text) return;

            // 1. Append User Message
            chatWindow.innerHTML += `<div class="msg user-msg">${text}</div>`;
            chatInput.value = '';
            chatWindow.scrollTop = chatWindow.scrollHeight;

            // 2. Append Loading Indicator
            const loaderId = 'ai-load-' + Date.now();
            chatWindow.innerHTML += `<div id="${loaderId}" class="msg ai-msg" style="opacity: 0.5;">Analyzing...</div>`;
            chatWindow.scrollTop = chatWindow.scrollHeight;

            try {
                // 3. Send to C2 Server (which acts as the AI proxy)
                const response = await fetch('https://sentinel-x-api.onrender.com/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: text })
                });
                
                const result = await response.json();
                document.getElementById(loaderId).remove();

                // 4. Append AI Response
                chatWindow.innerHTML += `<div class="msg ai-msg">${result.reply}</div>`;
                chatWindow.scrollTop = chatWindow.scrollHeight;
            } catch (err) {
                document.getElementById(loaderId).remove();
                chatWindow.innerHTML += `<div class="msg ai-msg" style="border-left-color: #F2555A;">[!] C2 Uplink Failed. AI offline.</div>`;
            }
        };

        sendChat.addEventListener('click', handleSend);
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') handleSend();
        });
    }
});