import express from 'express';
import pg from 'pg';
const { Pool } = pg;
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';

// Carrega variáveis de ambiente
dotenv.config();

// Configuração do pool usando a string de conexão diretamente
const pool = new Pool({
  connectionString: process.env.DB_CONNECTION_STRING,
  ssl: {
    rejectUnauthorized: true
  },
  max: 20,
  idleTimeoutMillis: 30000
});

// Teste de conexão
pool.query('SELECT 1')
  .then(() => console.log('✅ Conexão com Neon estabelecida com sucesso!'))
  .catch(err => {
    console.error('❌ Falha na conexão com Neon:', err.message);
    process.exit(1);
  });

const app = express();
const port = process.env.PORT || 3000;

// Middlewares
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Autenticação com JWT
const revokedTokens = new Set();

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  if (revokedTokens.has(token)) return res.status(403).json({ error: 'Sessão expirada. Faça login novamente.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido ou expirado' });

    req.user = decoded;
    next();
  });
};

// Rotas públicas
app.post('/signup', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    const userExists = await pool.query('SELECT 1 FROM usuarios WHERE username = $1', [username]);
    if (userExists.rowCount > 0) {
      return res.status(400).json({ error: 'Usuário já existe' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO usuarios (username, password_hash, email) VALUES ($1, $2, $3) RETURNING id',
      [username, passwordHash, email]
    );
    res.status(201).json({ message: 'Usuário criado com sucesso', userId: rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao criar usuário' });
  }
});

app.post('/login', async (req, res) => {
  try {
    console.log('--- Nova tentativa de login ---');
    console.log('Corpo da requisição recebida:', req.body);

    const { username, password } = req.body;

    if (!username || !password) {
      console.warn('Usuário ou senha não enviados');
      return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });
    }

    const { rows } = await pool.query(
      'SELECT id, password_hash FROM usuarios WHERE username = $1', 
      [username]
    );

    console.log(`Resultado da consulta no banco para o usuário ${username}:`, rows);

    if (rows.length === 0) {
      console.warn('Usuário não encontrado no banco');
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const user = rows[0];

    const isValid = await bcrypt.compare(password, user.password_hash);
    console.log('Senha válida?', isValid);

    if (!isValid) {
      console.warn('Senha incorreta para o usuário:', username);
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET não definida no ambiente!');
      return res.status(500).json({ error: 'Erro interno de configuração' });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );

    console.log('Token gerado com sucesso:', token);

    res.json({ token });
  } catch (err) {
    console.error('Erro no processo de login:', err);
    res.status(500).json({ error: 'Erro no login' });
  }
});
app.post('/novo', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Verifica se o username já existe
    const { rows } = await pool.query(
      'SELECT id FROM usuarios WHERE username = $1', 
      [username]
    );

    if (rows.length > 0) {
      return res.status(400).json({ error: 'Usuário já existe' });
    }

    // Criptografa a senha antes de salvar
    const passwordHash = await bcrypt.hash(password, 10);

    // Insere o novo usuário no banco
    const result = await pool.query(
      'INSERT INTO usuarios (username, password_hash) VALUES ($1, $2) RETURNING id', 
      [username, passwordHash]
    );

    res.status(201).json({ message: 'Usuário cadastrado com sucesso', userId: result.rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao cadastrar usuário' });
  }
});


app.post('/logout', authenticateToken, (req, res) => {
  revokedTokens.add(req.headers['authorization']?.split(' ')[1]);
  res.json({ message: 'Logout realizado com sucesso' });
});

// Rota de verificação
app.get('/',  async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT current_database(), current_user, now() as server_time'
    );
    res.json({
      status: 'online',
      database: rows[0].current_database,
      user: rows[0].current_user,
      time: rows[0].server_time,
      neon: true
    });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err.message });
  }
});

// Clientes
app.get('/clientes', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM clientes LIMIT 100');
    res.json({
      success: true,
      count: rows.length,
      data: rows
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: 'Database error',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

app.post('/clientes', authenticateToken, async (req, res) => {
  try {
    const { nome, whatsapp, vencimento, plano, endereco } = req.body;
    const { rows } = await pool.query(
      `INSERT INTO clientes (nome, whatsapp, vencimento, plano, endereco) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [nome, whatsapp, vencimento, plano, endereco]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      res.status(400).json({ error: 'WhatsApp já cadastrado' });
    } else {
      console.error(err);
      res.status(500).json({ error: 'Erro ao criar cliente' });
    }
  }
});

// Pagamentos
app.get('/clientes/:id/pagamentos', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, year, month } = req.query;

    const clienteExists = await pool.query('SELECT 1 FROM clientes WHERE id = $1', [id]);
    if (clienteExists.rowCount === 0) {
      return res.status(404).json({ error: 'Cliente não encontrado' });
    }

    let query = 'SELECT * FROM pagamentos WHERE cliente_id = $1';
    const params = [id];
    let paramIndex = 2;

    if (status) {
      query += ` AND status = $${paramIndex}`;
      params.push(status);
      paramIndex++;
    }

    if (year) {
      query += ` AND EXTRACT(YEAR FROM data_vencimento) = $${paramIndex}`;
      params.push(year);
      paramIndex++;
    }

    if (month) {
      query += ` AND EXTRACT(MONTH FROM data_vencimento) = $${paramIndex}`;
      params.push(month);
    }

    query += ' ORDER BY data_vencimento DESC';
    const { rows } = await pool.query(query, params);

    res.status(200).json(rows);
  } catch (err) {
    console.error('Erro detalhado:', {
      message: err.message,
      stack: err.stack,
      query: err.query
    });
    res.status(500).json({ 
      error: 'Erro ao buscar pagamentos',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

app.post('/pagamentos', authenticateToken, async (req, res) => {
  try {
    const { cliente_id, valor, data_vencimento, referencia } = req.body;
    const { rows } = await pool.query(
      `INSERT INTO pagamentos (cliente_id, valor, data_vencimento, referencia)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [cliente_id, valor, data_vencimento, referencia]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao registrar pagamento' });
  }
});

export default app;
