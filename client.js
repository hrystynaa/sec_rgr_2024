const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const forge = require('node-forge');
const readline = require('readline');

const HOST = 'localhost';
const PORT = 65432;
const ROOT_CA_CERT_FILE = 'root_ca.crt';

let rootCaCertPem, rootCaCertForge;
try {
    console.log('Loading trusted Root CA certificate...');
    rootCaCertPem = fs.readFileSync(ROOT_CA_CERT_FILE, 'utf8');
    rootCaCertForge = forge.pki.certificateFromPem(rootCaCertPem);
    console.log(`Root CA certificate loaded successfully (Subject: ${rootCaCertForge.subject.getField('CN')?.value}).`);
} catch (err) {process.exit(1); }

function generateSessionKey(clientRandom, serverRandom, premasterSecret) {
    const hash = crypto.createHash('sha256'); 
    hash.update(clientRandom); hash.update(serverRandom); 
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
    try { const iv = encryptedBuffer.subarray(0, IV_LENGTH); 
      const authTag = encryptedBuffer.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH); 
      const ciphertext = encryptedBuffer.subarray(IV_LENGTH + AUTH_TAG_LENGTH); 
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv); decipher.setAuthTag(authTag); 
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]); 
      return decrypted; 
    } catch (error) { 
      console.error("Decryption failed:", error.message); 
      return null; 
    }
}
function verifyServerCertificate(serverCertPem, caCert) {
    console.log("Client: Verifying server certificate..."); 
    try { const serverCert = forge.pki.certificateFromPem(serverCertPem); 
    const caStore = forge.pki.createCaStore(); 
    caStore.addCertificate(caCert); 
    forge.pki.verifyCertificateChain(caStore, [serverCert]); console.log("Client: Certificate chain ... verified successfully."); 
    const cn = serverCert.subject.getField('CN')?.value; 
    if (!cn) { 
      console.error("Error: Server certificate missing Common Name (CN).");
      return null; 
    } 
    if (cn.toLowerCase() !== HOST.toLowerCase()) { 
      console.error(`Error: Certificate CN ('${cn}') does not match expected host ('${HOST}').`); 
      return null; 
    } 
    console.log(`Client: Common Name ('${cn}') matches host.`); 
    console.log("Client: Server certificate verified successfully!"); 
    return serverCert; 
  } catch (err) { 
    console.error(`Client: Certificate verification failed: ${err.message || err}`); 
    if (err.details) { 
      console.error("Details:", err.details); 
    } 
    return null; 
  }
}

const client = net.createConnection({ host: HOST, port: PORT }, () => {
    console.log(`Client connected to ${HOST}:${PORT}`);
    clientRandomInternal = crypto.randomBytes(32);
    client.write(clientRandomInternal); 
    console.log(`Client: Sent Client Hello (random): ${clientRandomInternal.toString('hex')}`);
    state = 'WAIT_SERVER_HELLO';
});

let state = 'CONNECTING';
let receivedData = Buffer.alloc(0);
let clientRandomInternal;
let serverRandomInternal;
let sessionKeyInternal;
let serverPublicKeyCrypto;

client.on('data', (data) => {
  receivedData = Buffer.concat([receivedData, data]);
    console.log(`Client: Received ${data.length} bytes. Total buffer: ${receivedData.length} bytes.`);

    try {
      if (state === 'WAIT_SERVER_HELLO') {
        if (!serverRandomInternal && receivedData.length >= 32) {
          serverRandomInternal = receivedData.subarray(0, 32);
          receivedData = receivedData.subarray(32);
          console.log(`Client: Processed Server Random: ${serverRandomInternal.toString('hex')}`);
        }
        if (serverRandomInternal && receivedData.length > 0) {
          const serverCertPem = receivedData.toString('utf8'); 
          receivedData = Buffer.alloc(0); 
          console.log(`Client: Remaining data is server certificate (${serverCertPem.length} bytes).`);
          const verifiedServerCertForge = verifyServerCertificate(serverCertPem, rootCaCertForge);
          if (!verifiedServerCertForge) { 
            client.end(); 
            return; 
          }
          const serverPublicKeyPem = forge.pki.publicKeyToPem(verifiedServerCertForge.publicKey);
          serverPublicKeyCrypto = crypto.createPublicKey(serverPublicKeyPem);
          console.log("Client: Server public key extracted from valid certificate.");
          const premasterSecret = crypto.randomBytes(48);
          console.log(`Client: Generated Premaster Secret.`);
          const encryptedPremasterSecret = crypto.publicEncrypt({ key: serverPublicKeyCrypto, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, premasterSecret);
          client.write(encryptedPremasterSecret);
          console.log("Client: Sent encrypted Premaster Secret.");
          sessionKeyInternal = generateSessionKey(clientRandomInternal, serverRandomInternal, premasterSecret);
          console.log(`Client: Session key generated.`);
          const clientReadyMessage = Buffer.from("Client Ready", 'utf8');
          const encryptedClientReady = encryptSymmetric(sessionKeyInternal, clientReadyMessage);
          client.write(encryptedClientReady);
          console.log("Client: Sent encrypted 'Client Ready' message.");
          state = 'WAIT_SERVER_READY';
        }
      } else if (state === 'WAIT_SERVER_READY') {
        if (receivedData.length > 0) {
          const encryptedServerReady = receivedData;
          receivedData = Buffer.alloc(0);
          console.log(`Client: Received data is encrypted Server Ready (${encryptedServerReady.length} bytes).`);
          const decryptedServerReady = decryptSymmetric(sessionKeyInternal, encryptedServerReady);
          if (!decryptedServerReady) {
            client.end(); 
            return; 
          }
          const serverReadyMessage = decryptedServerReady.toString('utf8');
          console.log(`Client: Received and decrypted from server: '${serverReadyMessage}'`);
          if (serverReadyMessage !== "Server Ready") {
            client.end(); 
            return; 
          }
          console.log("\n--- TLS/SSL Handshake potentially completed ---");
          console.log("--- Secure communication channel established ---");
          state = 'SECURE_COMMUNICATION';
          promptForInput();
        }
      } else if (state === 'SECURE_COMMUNICATION') {
        if (receivedData.length > 0) {
          const encryptedData = receivedData;
          receivedData = Buffer.alloc(0);
          console.log(`Client: Received data is encrypted message (${encryptedData.length} bytes).`);
          const decryptedData = decryptSymmetric(sessionKeyInternal, encryptedData);
          if (decryptedData) {                      
            console.log(`Received (decrypted): ${decryptedData.toString('utf8')}`);
            promptForInput();
          } else {
            console.error("Client: Failed to decrypt data from server.");
            promptForInput();
          }
        }
      }
    } catch (err) {
      console.error('Client: Error processing incoming data:', err);
      client.end();
    }
});

client.on('end', () => {
  console.log('Disconnected from server.');
  if (rl) rl.close();
  process.exit(0);
});

client.on('error', (err) => {
  if (err.code === 'ECONNREFUSED') {
       console.error(`Error: Connection refused by ${HOST}:${PORT}. Make sure the server is running.`);
  } else {
      console.error(`Client connection error: ${err.message}`);
  }
   if (rl) rl.close();
  process.exit(1);
});

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
rl.on('SIGINT', () => { console.log('\nDisconnecting...'); client.end(); rl.close(); });

function promptForInput() {
    if (state !== 'SECURE_COMMUNICATION' || !client.writable) { if (rl && !rl.closed) rl.close(); return; }
    rl.question('Клієнт > ', (message) => {
        if (!client.writable) { console.log("Cannot send message, connection closed."); rl.close(); return; }
        if (message.toLowerCase() === 'exit') { client.end(); rl.close(); return; }
        if (state === 'SECURE_COMMUNICATION' && sessionKeyInternal) {
             const encryptedMessage = encryptSymmetric(sessionKeyInternal, Buffer.from(message, 'utf8'));
             client.write(encryptedMessage);
        } else { console.log("Cannot send data yet."); if (state === 'SECURE_COMMUNICATION') promptForInput(); }
    });
}