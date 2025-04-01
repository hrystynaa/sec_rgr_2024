const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const forge = require('node-forge');

const HOST = 'localhost';
const PORT = 65432;
const SERVER_CERT_FILE = 'server.crt';
const SERVER_KEY_FILE = 'server.key';

let privateKeyPem, privateKeyObject, serverCertPem, serverCertBuffer;
try {
    console.log('Loading server private key...');
    privateKeyPem = fs.readFileSync(SERVER_KEY_FILE, 'utf8');
    privateKeyObject = crypto.createPrivateKey(privateKeyPem);
    console.log('Server private key loaded successfully.');

    console.log('Loading server certificate...');
    serverCertPem = fs.readFileSync(SERVER_CERT_FILE, 'utf8');
    serverCertBuffer = Buffer.from(serverCertPem, 'utf8'); 
    const serverCertForge = forge.pki.certificateFromPem(serverCertPem);
    console.log(`Server certificate loaded successfully (Subject: ${serverCertForge.subject.getField('CN')?.value}).`);
} catch (err) {
    console.error('Error loading server files (check server.key and server.crt):', err);
    process.exit(1);
}

function generateSessionKey(clientRandom, serverRandom, premasterSecret) { 
    const hash = crypto.createHash('sha256');
    hash.update(clientRandom);
    hash.update(serverRandom);
    hash.update(premasterSecret);
    return hash.digest();
}
const IV_LENGTH = 12; const AUTH_TAG_LENGTH = 16;
function encryptSymmetric(key, plaintextBuffer) { 
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, encrypted]);
}
function decryptSymmetric(key, encryptedBuffer) { 
    try {
        const iv = encryptedBuffer.subarray(0, IV_LENGTH);
        const authTag = encryptedBuffer.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
        const ciphertext = encryptedBuffer.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return decrypted;
    } catch (error) {
        console.error("Decryption failed (authentication tag mismatch?):", error.message);
        return null;
    }
}

const server = net.createServer((socket) => {
    console.log(`Client connected: ${socket.remoteAddress}:${socket.remotePort}`);

    let state = 'WAIT_CLIENT_HELLO';
    let receivedData = Buffer.alloc(0);
    let clientRandom, serverRandom, premasterSecret, sessionKey;

    socket.on('data', (data) => {
        receivedData = Buffer.concat([receivedData, data]);
        console.log(`Server: Received ${data.length} bytes. Total buffer: ${receivedData.length} bytes.`); 

        try {
            if (state === 'WAIT_CLIENT_HELLO') {
                if (receivedData.length >= 32) { 
                    clientRandom = receivedData.subarray(0, 32);
                    receivedData = receivedData.subarray(32); 
                    console.log(`Server: Processed Client Hello (random): ${clientRandom.toString('hex')}`);

                    serverRandom = crypto.randomBytes(32);
                    console.log(`Server: Generated Server Random: ${serverRandom.toString('hex')}`);

                    socket.write(serverRandom);
                    socket.write(serverCertBuffer);
                    console.log("Server: Sent Server Random and Server Certificate.");
                    state = 'WAIT_PREMASTER_SECRET';
                }
            } else if (state === 'WAIT_PREMASTER_SECRET') {
                 if (receivedData.length > 0) {
                    const encryptedPremasterSecret = receivedData;
                    receivedData = Buffer.alloc(0); 
                    console.log(`Server: Received data is encrypted Premaster Secret (${encryptedPremasterSecret.length} bytes).`);

                    try {
                        premasterSecret = crypto.privateDecrypt({ key: privateKeyObject, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, encryptedPremasterSecret);
                        console.log(`Server: Premaster Secret decrypted successfully: ${premasterSecret.toString('hex')}`);
                    } catch (e) {
                        console.error(`Server: Failed to decrypt Premaster Secret: ${e.message} (DATA MIGHT BE CORRUPTED/INCOMPLETE)`);
                        socket.end(); return;
                    }

                    sessionKey = generateSessionKey(clientRandom, serverRandom, premasterSecret);
                    console.log(`Server: Session key generated.`);
                    state = 'WAIT_CLIENT_READY';
                 }
            } else if (state === 'WAIT_CLIENT_READY') {
                 if (receivedData.length > 0) {
                    const encryptedClientReady = receivedData;
                     receivedData = Buffer.alloc(0);
                    console.log(`Server: Received data is encrypted Client Ready (${encryptedClientReady.length} bytes).`);

                    const decryptedClientReady = decryptSymmetric(sessionKey, encryptedClientReady);
                    if (!decryptedClientReady) { socket.end(); return; }

                    const clientReadyMessage = decryptedClientReady.toString('utf8');
                    console.log(`Server: Received and decrypted from client: '${clientReadyMessage}'`);
                    if (clientReadyMessage !== "Client Ready") { socket.end(); return; }

                    const serverReadyMessage = Buffer.from("Server Ready", 'utf8');
                    const encryptedServerReady = encryptSymmetric(sessionKey, serverReadyMessage);
                    socket.write(encryptedServerReady); 
                    console.log("Server: Sent encrypted 'Server Ready' message.");

                    console.log("\n--- TLS/SSL Handshake potentially completed ---");
                    console.log("--- Secure communication channel established ---");
                    state = 'SECURE_COMMUNICATION';
                 }
            } else if (state === 'SECURE_COMMUNICATION') {
                 if (receivedData.length > 0) {
                    const encryptedData = receivedData;
                    receivedData = Buffer.alloc(0);
                    console.log(`Server: Received data is encrypted message (${encryptedData.length} bytes).`);

                    const decryptedData = decryptSymmetric(sessionKey, encryptedData);
                    if (!decryptedData) { console.error("Server: Failed to decrypt client data."); return; }

                    const message = decryptedData.toString('utf8');
                    console.log(`Received (decrypted): ${message}`);

                    const response = Buffer.from(`Server received: '${message}'`, 'utf8');
                    const encryptedResponse = encryptSymmetric(sessionKey, response);
                    socket.write(encryptedResponse); 
                 }
            }
        } catch (err) {
            console.error('Error processing incoming data:', err);
            socket.end();
        }
    });

    socket.on('end', () => { console.log('Client disconnected.'); });
    socket.on('error', (err) => { console.error(`Socket error: ${err.message}`); });
});

server.listen(PORT, HOST, () => { console.log(`Server listening on ${HOST}:${PORT}...`); });
server.on('error', (err) => { console.error(`Server error: ${err.message}`); });