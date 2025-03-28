// server2.cjs
const express = require('express');
const cors = require('cors');
const { Client } = require('ssh2');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const selfsigned = require('selfsigned');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(cors());

// Gerar ou carregar certificados automaticamente
let httpsOptions;
try {
  const key = fs.readFileSync('key.pem');
  const cert = fs.readFileSync('cert.pem');
  httpsOptions = { key, cert };
  console.log('Certificados encontrados e carregados.');
} catch (err) {
  console.log('Certificados não encontrados, gerando novos certificados autoassinados...');
  const attrs = [{ name: 'commonName', value: 'localhost' }];
  const pems = selfsigned.generate(attrs, { days: 365 });
  fs.writeFileSync('key.pem', pems.private);
  fs.writeFileSync('cert.pem', pems.cert);
  httpsOptions = { key: pems.private, cert: pems.cert };
  console.log('Novos certificados gerados e salvos.');
}

// In-memory session store para associar tokens às credenciais
const sessions = {};

// Função auxiliar para extrair o token do cabeçalho Authorization
function getToken(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;
  const parts = authHeader.split(' ');
  if (parts.length !== 2) return null;
  if (parts[0] !== 'Bearer') return null;
  return parts[1];
}

// Endpoint de Health
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK' });
});

// Endpoint de Login via SSH
app.post('/api/login', (req, res) => {
  const { server, username, password } = req.body;
  if (!server || !username || !password) {
    return res.status(400).json({ message: 'Dados insuficientes para login' });
  }
  
  const conn = new Client();
  conn.on('ready', () => {
    console.log(`Conexão SSH estabelecida com ${server}`);
    // Gera um token para a sessão
    const token = crypto.randomBytes(16).toString('hex');
    // Armazena as credenciais na sessão (em memória)
    sessions[token] = { server, username, password };
    res.json({ message: `Conexão SSH estabelecida com sucesso em ${server}`, token });
    conn.end();
  }).on('error', (err) => {
    console.error('Erro na conexão SSH:', err);
    res.status(500).json({ message: 'Erro na conexão SSH: ' + err.message });
  }).connect({
    host: server,
    port: 22,
    username: username,
    password: password,
  });
});

// Endpoint para listar conteúdo de diretório
app.post('/api/list', (req, res) => {
  const token = getToken(req);
  if (!token || !sessions[token]) {
    return res.status(401).json({ message: 'Token inválido ou ausente' });
  }
  const { server, username, password } = sessions[token];
  const { path } = req.body;
  if (path === undefined) {
    return res.status(400).json({ message: 'Dados insuficientes para listar diretório' });
  }
  
  const conn = new Client();
  conn.on('ready', () => {
    // Executa o comando ls -p para identificar diretórios (com barra no final)
    conn.exec(`ls -p "${path}"`, (err, stream) => {
      if (err) {
        conn.end();
        return res.status(500).json({ message: 'Erro ao executar comando: ' + err.message });
      }
      let output = '';
      stream.on('data', (data) => { output += data.toString(); })
      .on('close', () => {
         conn.end();
         const lines = output.split('\n').filter(line => line.trim() !== '');
         const items = lines.map(item => {
           if (item.endsWith('/')) {
             return { name: item.slice(0, -1), type: 'dir' };
           } else {
             return { name: item, type: 'file' };
           }
         });
         res.json({ items });
      });
    });
  }).on('error', (err) => {
    res.status(500).json({ message: 'Erro na conexão SSH: ' + err.message });
  }).connect({
    host: server,
    port: 22,
    username: username,
    password: password,
  });
});

// Endpoint para obter o caminho absoluto de um arquivo/diretório
app.post('/api/realpath', (req, res) => {
  const token = getToken(req);
  if (!token || !sessions[token]) {
    return res.status(401).json({ message: 'Token inválido ou ausente' });
  }
  const { server, username, password } = sessions[token];
  const { targetPath } = req.body;
  if (!targetPath) {
    return res.status(400).json({ message: 'Dados insuficientes para obter o caminho absoluto' });
  }
  
  const conn = new Client();
  conn.on('ready', () => {
    conn.exec(`realpath "${targetPath}"`, (err, stream) => {
      if (err) {
        conn.end();
        return res.status(500).json({ message: 'Erro ao executar comando: ' + err.message });
      }
      let output = '';
      stream.on('data', (data) => { output += data.toString(); })
      .on('close', () => {
         conn.end();
         res.json({ absolutePath: output.trim() });
      });
    });
  }).on('error', (err) => {
    res.status(500).json({ message: 'Erro na conexão SSH: ' + err.message });
  }).connect({
    host: server,
    port: 22,
    username: username,
    password: password,
  });
});

// Cria o servidor HTTPS com os certificados gerados ou carregados
https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`Servidor seguro rodando na porta ${PORT}`);
});
