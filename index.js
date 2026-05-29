const net = require('net');
const crypto = require('crypto');

const PASSWORD = process.env.SS_PASSWORD || 'mypassword123';
const PORT = process.env.PORT || 10000;

const CIPHER = 'aes-256-cfb';

function createCipher(password) {
  const key = crypto.scryptSync(password, 'salt', 32);
  const iv = crypto.randomBytes(16);
  return { cipher: crypto.createCipheriv(CIPHER, key, iv), iv };
}

function createDecipher(password, iv) {
  const key = crypto.scryptSync(password, 'salt', 32);
  return crypto.createDecipheriv(CIPHER, key, iv);
}

const server = net.createServer((socket) => {
  let decipher = null;
  let iv = Buffer.alloc(0);
  let ivCollected = false;

  socket.on('data', (data) => {
    try {
      if (!ivCollected) {
        iv = Buffer.concat([iv, data]);
        if (iv.length >= 16) {
          const realIV = iv.slice(0, 16);
          decipher = createDecipher(PASSWORD, realIV);
          const rest = iv.slice(16);
          iv = realIV;
          ivCollected = true;
          if (rest.length > 0) socket.emit('data', rest);
        }
        return;
      }

      const decrypted = decipher.update(data);
      const atyp = decrypted[0];
      let host, port, headerLen;

      if (atyp === 0x01) {
        host = `${decrypted[1]}.${decrypted[2]}.${decrypted[3]}.${decrypted[4]}`;
        port = decrypted.readUInt16BE(5);
        headerLen = 7;
      } else if (atyp === 0x03) {
        const len = decrypted[1];
        host = decrypted.slice(2, 2 + len).toString();
        port = decrypted.readUInt16BE(2 + len);
        headerLen = 4 + len;
      } else return;

      const remote = net.connect(port, host, () => {
        remote.write(decrypted.slice(headerLen));
        socket.pipe(remote);
        remote.pipe(socket);
      });

      remote.on('error', () => socket.destroy());
    } catch (e) {
      socket.destroy();
    }
  });

  socket.on('error', () => {});
});

server.listen(PORT, () => {
  console.log(`Shadowsocks server running on port ${PORT}`);
});
