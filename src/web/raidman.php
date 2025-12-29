<?php
// Secure separation
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Raidman Terminal</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.1.0/css/xterm.css" />
    <style>
        body {
            margin: 0;
            padding: 0;
            background-color: #000;
            height: 100vh;
            width: 100vw;
            overflow: hidden;
        }

        #terminal {
            height: 100%;
            width: 100%;
        }
    </style>
</head>

<body>
    <div id="terminal"></div>
    <script src="https://cdn.jsdelivr.net/npm/xterm@5.1.0/lib/xterm.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.7.0/lib/xterm-addon-fit.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-web-links@0.8.0/lib/xterm-addon-web-links.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-attach@0.8.0/lib/xterm-addon-attach.js"></script>
    <script>
        // Parse Query Params
        const urlParams = new URLSearchParams(window.location.search);
        const apiKey = urlParams.get('x-api-key');
        const type = urlParams.get('type') || 'docker';
        const container = urlParams.get('container') || '';
        const vm = urlParams.get('vm') || '';

        if (!apiKey) {
            document.body.innerHTML = '<h1 style="color:white;text-align:center">Error: Missing API Key</h1>';
            throw new Error("Missing API Key");
        }

        // Initialize Terminal
        const term = new Terminal({
            theme: {
                background: '#000000',
                foreground: '#ffffff',
                cursor: '#f15a24'
            },
            cursorBlink: true,
            fontSize: 14,
            fontFamily: 'Menlo, Monaco, "Courier New", monospace'
        });

        // Initialize Addons
        try {
            const fitAddon = new FitAddon.FitAddon();
            term.loadAddon(fitAddon);
            const webLinksAddon = new WebLinksAddon.WebLinksAddon();
            term.loadAddon(webLinksAddon);

            term.open(document.getElementById('terminal'));
            fitAddon.fit();

            window.addEventListener('resize', () => {
                fitAddon.fit();
            });

            // WebSocket Connection
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            // Use native Unraid proxy path: /logterminal/{socketName}/{path}
            // Socket: raidman (mapped to /var/tmp/raidman.sock)
            // Path: connect
            const wsUrl = `${protocol}//${window.location.host}/logterminal/raidman/connect?x-api-key=${encodeURIComponent(apiKey)}&type=${encodeURIComponent(type)}&container=${encodeURIComponent(container)}&vm=${encodeURIComponent(vm)}`;

            const socket = new WebSocket(wsUrl);

            socket.onopen = () => {
                const attachAddon = new AttachAddon.AttachAddon(socket);
                term.loadAddon(attachAddon);
                term.focus();
            };

            socket.onerror = (error) => {
                console.error('WebSocket Error:', error);
                term.write('\r\n\x1b[31mConnection Error: ' + error + '\x1b[0m\r\n');
            };

            socket.onclose = () => {
                term.write('\r\n\x1b[33mConnection Closed\x1b[0m\r\n');
            };

        } catch (e) {
            console.error("Error initializes addons or terminal:", e);
            document.body.innerHTML = `<h1 style="color:red">Init Error: ${e.message}</h1>`;
        }
    </script>
</body>

</html>