const net = require('net');
const crypto = require('crypto');

const client = new net.Socket();
let serverPublicKey = null;
let sessionKey = null;

client.connect(3000, '127.0.0.1', () => {
  console.log('Connected to server');

  const helloMessage = `hello-${crypto.randomBytes(16).toString('hex')}`;
  client.write(helloMessage);
});

client.on('data', (data) => {
  const message = data.toString();
  console.log('Received from server:\n', message);

  if (!serverPublicKey) {
    try {
      serverPublicKey = crypto.createPublicKey(message);

      const premasterSecret = crypto.randomBytes(48);
      sessionKey = crypto.createHash('sha256').update(premasterSecret).digest();
      console.log('Session key created');
      const encryptedPremaster = crypto.publicEncrypt(serverPublicKey, premasterSecret);
      client.write(`premaster:${encryptedPremaster.toString('base64')}`);
      console.log('Premaster secret encrypted');
    } catch (error) {
      console.error('Error handling server key:', error.message);
    }
  } else if (sessionKey) {
    try {
      const decryptedMessage = decryptMessage(message, sessionKey);

      if (decryptedMessage === 'ready') {
        console.log('Server is ready for data exchange');
        const secureMessage = encryptMessage('This message was sent over a secure channel', sessionKey);
        client.write(secureMessage);
      } else {
        console.log('Decoded server message:', decryptedMessage);
      }

    } catch (error) {
      console.error('Error decrypting message:', error.message);
    }
  }
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
