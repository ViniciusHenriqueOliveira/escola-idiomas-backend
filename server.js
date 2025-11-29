// server.js
require('dotenv').config(); // Carrega as variáveis de ambiente do .env
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// --- Configuração do Banco de Dados (Supabase/PostgreSQL) ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Em ambientes de deploy como o Render, pode ser necessário configurar SSL:
    // ssl: { rejectUnauthorized: false }
});

// --- Middlewares Essenciais ---
app.use(cors()); // Permite requisições do front-end (CORS)
app.use(express.json()); // Permite que o Express leia o body das requisições como JSON

// --- Middleware de Autenticação JWT ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    // Espera o formato "Bearer [token]"
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ error: 'Token de autenticação necessário.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            // Se o token for inválido/expirado, força o logout no front-end (Status 403)
            return res.status(403).json({ error: 'Token inválido ou expirado. Faça login novamente.' });
        }
        req.user = user; // Adiciona o payload do token (id, nome) à requisição
        next();
    });
}

// --- ROTAS DE TESTE E RAÍZ ---
app.get('/', (req, res) => {
    res.send('API da Escola de Idiomas está rodando e conectada ao banco de dados.');
});


// ----------------------------------------------------------------
// --- ROTAS DE AUTENTICAÇÃO (RF01, RF02) ---
// ----------------------------------------------------------------

// RF01 - Cadastro de Usuários
app.post('/api/usuarios/cadastro', async (req, res) => {
    const { nome, email, senha } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const senha_hash = await bcrypt.hash(senha, salt);
        
        const result = await pool.query(
            'INSERT INTO usuarios (nome, email, senha_hash) VALUES ($1, $2, $3) RETURNING id, nome, email',
            [nome, email, senha_hash]
        );
        res.status(201).json({ message: 'Usuário cadastrado com sucesso!', usuario: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') { // Erro de violação de unique constraint (e-mail já existe)
            return res.status(409).json({ error: 'E-mail já cadastrado.' });
        }
        console.error("Erro no cadastro:", err);
        res.status(500).json({ error: 'Erro interno do servidor ao cadastrar.' });
    }
});

// RF02 - Login de Usuário
app.post('/api/login', async (req, res) => {
    const { email, senha } = req.body;
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(400).json({ error: 'E-mail ou senha incorretos.' });
        }

        const isMatch = await bcrypt.compare(senha, user.senha_hash);
        if (!isMatch) {
            return res.status(400).json({ error: 'E-mail ou senha incorretos.' });
        }

        // Gera o token JWT com o payload (RF02)
        const payload = { id: user.id, nome: user.nome };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

        // Retorna o token e o usuário
        res.json({ token, usuario: { id: user.id, nome: user.nome, email: user.email } });
    } catch (err) {
        console.error("Erro no login:", err);
        res.status(500).json({ error: 'Erro interno do servidor ao logar.' });
    }
});


// ----------------------------------------------------------------
// --- ROTAS DE TURMAS E MATRÍCULAS (RF03, RF04) ---
// ----------------------------------------------------------------

// RF03 - CRIAÇÃO de Turma
app.post('/api/turmas', authenticateToken, async (req, res) => {
    const { nome, nivel, professor, horario } = req.body;
    const usuario_criador_id = req.user.id; 
    try {
        const result = await pool.query(
            'INSERT INTO turmas (nome, nivel, professor, horario, usuario_criador_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [nome, nivel, professor, horario, usuario_criador_id]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error("Erro ao criar turma:", err);
        res.status(500).json({ error: 'Erro ao criar turma.' });
    }
});

// RF04 - LEITURA (Listagem) de Turmas
app.get('/api/turmas', authenticateToken, async (req, res) => {
    const usuario_id = req.user.id;
    try {
        // Retorna todas as turmas e verifica se o usuário está matriculado em cada uma
        const query = `
            SELECT 
                t.*, 
                CASE 
                    WHEN m.usuario_id IS NOT NULL THEN TRUE 
                    ELSE FALSE 
                END AS esta_matriculado
            FROM turmas t
            LEFT JOIN matriculas m ON t.id = m.turma_id AND m.usuario_id = $1
            ORDER BY t.id DESC;
        `;
        const result = await pool.query(query, [usuario_id]);
        res.json(result.rows);
    } catch (err) {
        console.error("Erro ao listar turmas:", err);
        res.status(500).json({ error: 'Erro ao listar turmas.' });
    }
});

// RF03 - EXCLUSÃO de Turma (Apenas o criador pode excluir)
app.delete('/api/turmas/:id', authenticateToken, async (req, res) => {
    const turmaId = req.params.id;
    const usuario_criador_id = req.user.id;
    try {
        // 1. Verifica se o usuário logado é o criador da turma
        const checkResult = await pool.query('SELECT usuario_criador_id FROM turmas WHERE id = $1', [turmaId]);
        
        if (checkResult.rowCount === 0) {
            return res.status(404).json({ error: 'Turma não encontrada.' });
        }
        if (checkResult.rows[0].usuario_criador_id !== usuario_criador_id) {
            return res.status(403).json({ error: 'Você só pode excluir turmas que você criou.' });
        }
        
        // 2. Exclui a turma
        const deleteResult = await pool.query('DELETE FROM turmas WHERE id = $1', [turmaId]);
        
        if (deleteResult.rowCount === 1) {
            res.json({ message: 'Turma excluída com sucesso.' });
        } else {
            res.status(404).json({ error: 'Turma não encontrada para exclusão.' });
        }
    } catch (err) {
        console.error("Erro ao excluir turma:", err);
        res.status(500).json({ error: 'Erro ao excluir turma.' });
    }
});

// Matricular em uma turma
app.post('/api/matriculas/:turmaId', authenticateToken, async (req, res) => {
    const turmaId = req.params.turmaId;
    const usuarioId = req.user.id;
    try {
        await pool.query('INSERT INTO matriculas (usuario_id, turma_id) VALUES ($1, $2)', [usuarioId, turmaId]);
        res.status(201).json({ message: 'Matrícula realizada com sucesso!' });
    } catch (err) {
        if (err.code === '23505') { // Conflito (já matriculado - Chave Primária Duplicada)
            return res.status(409).json({ message: 'Você já está matriculado nesta turma.' });
        }
        console.error("Erro ao matricular:", err);
        res.status(500).json({ error: 'Erro ao matricular na turma.' });
    }
});

// Desmatricular de uma turma
app.delete('/api/matriculas/:turmaId', authenticateToken, async (req, res) => {
    const turmaId = req.params.turmaId;
    const usuarioId = req.user.id;
    try {
        const result = await pool.query('DELETE FROM matriculas WHERE usuario_id = $1 AND turma_id = $2', [usuarioId, turmaId]);
        
        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'Matrícula não encontrada.' });
        }
        res.json({ message: 'Desmatrícula realizada com sucesso.' });
    } catch (err) {
        console.error("Erro ao desmatricular:", err);
        res.status(500).json({ error: 'Erro ao desmatricular.' });
    }
});

// Listar alunos em uma turma (Função extra usada no front-end: handleViewAlunos)
app.get('/api/turmas/:turmaId/alunos', authenticateToken, async (req, res) => {
    const turmaId = req.params.turmaId;
    try {
        const query = `
            SELECT u.nome, u.email
            FROM usuarios u
            JOIN matriculas m ON u.id = m.usuario_id
            WHERE m.turma_id = $1
            ORDER BY u.nome;
        `;
        const result = await pool.query(query, [turmaId]);
        res.json(result.rows);
    } catch (err) {
        console.error("Erro ao buscar alunos:", err);
        res.status(500).json({ error: 'Erro ao buscar alunos.' });
    }
});

// ----------------------------------------------------------------
// --- CONEXÃO COM O BANCO E INICIALIZAÇÃO DO SERVIDOR ---
// ----------------------------------------------------------------

pool.connect()
    .then(() => {
        console.log('Conectado ao Supabase (PostgreSQL) com sucesso!');
        app.listen(PORT, () => {
            console.log(`Servidor rodando na porta http://localhost:${PORT}`); 
        });
    })
    .catch(err => {
        console.error('Erro ao conectar ao banco de dados:', err.stack);
        process.exit(1);
    });

// FIM DO server.js