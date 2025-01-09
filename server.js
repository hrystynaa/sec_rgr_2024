const net = require('net');
const crypto = require('crypto');

const serverKeyPair = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

let premasterSecret = null;
let sessionKey = null;

const server = net.createServer((socket) => {
  console.log('Client connected');

  socket.on('data', (data) => {
    const message = data.toString();
    console.log('Received from client:', message);

    if (message.startsWith('hello')) {
      socket.write(serverKeyPair.publicKey.export({ type: 'pkcs1', format: 'pem' }));
    } else if (message.startsWith('premaster:')) {
      const encryptedPremaster = Buffer.from(message.replace('premaster:', ''), 'base64');
      try {
        premasterSecret = crypto.privateDecrypt(serverKeyPair.privateKey, encryptedPremaster);
        console.log('Premaster secret decrypted');
        sessionKey = crypto.createHash('sha256').update(premasterSecret).digest();
        console.log('Session key created');

        const readyMessage = encryptMessage('ready', sessionKey);
        socket.write(readyMessage);
      } catch (error) {
        console.error('Error decrypting premaster secret:', error.message);
      }
    } else {
      try {
        const decryptedMessage = decryptMessage(message, sessionKey);
        console.log('Decoded message:', decryptedMessage);

        const responseMessage = encryptMessage('Hello from secure server!', sessionKey);
        socket.write(responseMessage);
      } catch (error) {
        console.error('Error decrypting message:', error.message);
      }
    }
  });
});

server.listen(3000, () => {
  console.log('Server running on port 3000');
});

function encryptMessage(message, key) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, key.slice(0, 16));
  let encrypted = cipher.update(message, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

function decryptMessage(encrypted, key) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, key.slice(0, 16));
  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
