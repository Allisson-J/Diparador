require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const multer = require('multer');
const csv = require('csv-parser');

const app = express();
const PORT = process.env.PORT || 5680;

// ========== CONFIGURAÇÃO EVOLUTION API ==========
const EVOLUTION_CONFIG = {
  baseUrl: process.env.EVOLUTION_BASE_URL,
};

// Adicionar validação para garantir que a variável existe
if (!EVOLUTION_CONFIG.baseUrl) {
  console.error('❌ ERRO CRÍTICO: EVOLUTION_BASE_URL não configurada no .env');
  process.exit(1);
}

// ========== CONFIGURAÇÃO MULTER PARA UPLOAD ==========
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, 'contatos-' + Date.now() + '.csv');
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: function (req, file, cb) {
    if (file.mimetype === 'text/csv' || file.originalname.endsWith('.csv')) {
      cb(null, true);
    } else {
      cb(new Error('Apenas arquivos CSV são permitidos'), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  }
});

// ========== DEBUG DAS VARIÁVEIS DE AMBIENTE ==========
console.log('🔧 DEBUG - Variáveis de ambiente carregadas:');
console.log('EVOLUTION_BASE_URL:', process.env.EVOLUTION_BASE_URL ? 'CONFIGURADA' : 'NÃO ENCONTRADA');
console.log('ADMIN_API_KEY:', process.env.ADMIN_API_KEY ? '***' + process.env.ADMIN_API_KEY.slice(-4) : 'NÃO ENCONTRADA');
console.log('ADMIN_INSTANCE_NAME:', process.env.ADMIN_INSTANCE_NAME || 'NÃO ENCONTRADA');
console.log('JBO_API_KEY:', process.env.JBO_API_KEY ? '***' + process.env.JBO_API_KEY.slice(-4) : 'NÃO ENCONTRADA');
console.log('JBO_INSTANCE_NAME:', process.env.JBO_INSTANCE_NAME || 'NÃO ENCONTRADA');
console.log('CABO_API_KEY:', process.env.CABO_API_KEY ? '***' + process.env.CABO_API_KEY.slice(-4) : 'NÃO ENCONTRADA');
console.log('CABO_INSTANCE_NAME:', process.env.CABO_INSTANCE_NAME || 'NÃO ENCONTRADA');
console.log('BA_API_KEY:', process.env.BA_API_KEY ? '***' + process.env.BA_API_KEY.slice(-4) : 'NÃO ENCONTRADA');
console.log('BA_INSTANCE_NAME:', process.env.BA_INSTANCE_NAME || 'NÃO ENCONTRADA');
console.log('PB_API_KEY:', process.env.PB_API_KEY ? '***' + process.env.PB_API_KEY.slice(-4) : 'NÃO ENCONTRADA');
console.log('PB_INSTANCE_NAME:', process.env.PB_INSTANCE_NAME || 'NÃO ENCONTRADA');
console.log('SP_API_KEY:', process.env.SP_API_KEY ? '***' + process.env.SP_API_KEY.slice(-4) : 'NÃO ENCONTRADA');
console.log('SP_INSTANCE_NAME:', process.env.SP_INSTANCE_NAME || 'NÃO ENCONTRADA');
console.log('AL_API_KEY:', process.env.AL_API_KEY ? '***' + process.env.AL_API_KEY.slice(-4) : 'NÃO ENCONTRADA');
console.log('AL_INSTANCE_NAME:', process.env.AL_INSTANCE_NAME || 'NÃO ENCONTRADA');
console.log('AMBEV_API_KEY:', process.env.AMBEV_API_KEY ? '***' + process.env.AMBEV_API_KEY.slice(-4) : 'NÃO ENCONTRADA');
console.log('AMBEV_INSTANCE_NAME:', process.env.AMBEV_INSTANCE_NAME || 'NÃO ENCONTRADA');
console.log('USINA_API_KEY:', process.env.USINA_API_KEY ? '***' + process.env.USINA_API_KEY.slice(-4) : 'NÃO ENCONTRADA');
console.log('USINA_INSTANCE_NAME:', process.env.USINA_INSTANCE_NAME || 'NÃO ENCONTRADA');

// ========== CONFIGURAÇÕES POR USUÁRIO ==========
function getEvolutionConfigByUser(usuario) {
  const userConfigs = {
    'admin': {
      apiKey: process.env.ADMIN_API_KEY,
      instanceName: process.env.ADMIN_INSTANCE_NAME,
      webhookUrl: process.env.ADMIN_WEBHOOK_URL
    },
    'JBO': {
      apiKey: process.env.JBO_API_KEY,
      instanceName: process.env.JBO_INSTANCE_NAME,
      webhookUrl: process.env.JBO_WEBHOOK_URL
    },
    'CABO': {
      apiKey: process.env.CABO_API_KEY,
      instanceName: process.env.CABO_INSTANCE_NAME,
      webhookUrl: process.env.CABO_WEBHOOK_URL
    },
    'BA': {
      apiKey: process.env.BA_API_KEY,
      instanceName: process.env.BA_INSTANCE_NAME,
      webhookUrl: process.env.BA_WEBHOOK_URL
    },
    'PB': {
      apiKey: process.env.PB_API_KEY,
      instanceName: process.env.PB_INSTANCE_NAME,
      webhookUrl: process.env.PB_WEBHOOK_URL
    },
    'SP': {
      apiKey: process.env.SP_API_KEY,
      instanceName: process.env.SP_INSTANCE_NAME,
      webhookUrl: process.env.SP_WEBHOOK_URL
    },
    'AL': {
      apiKey: process.env.AL_API_KEY,
      instanceName: process.env.AL_INSTANCE_NAME,
      webhookUrl: process.env.AL_WEBHOOK_URL
    },
    'AMBEV': {
      apiKey: process.env.AMBEV_API_KEY,
      instanceName: process.env.AMBEV_INSTANCE_NAME,
      webhookUrl: process.env.AMBEV_WEBHOOK_URL
    },
    'USINA': {
      apiKey: process.env.USINA_API_KEY,
      instanceName: process.env.USINA_INSTANCE_NAME,
      webhookUrl: process.env.USINA_WEBHOOK_URL
    }
  };
  
  const config = userConfigs[usuario];
  
  if (!config) {
    console.error(`❌ Usuário não encontrado: ${usuario}`);
    return {
      apiKey: process.env.ADMIN_API_KEY,
      instanceName: process.env.ADMIN_INSTANCE_NAME,
      webhookUrl: process.env.ADMIN_WEBHOOK_URL,
      error: `Usuário ${usuario} não configurado`
    };
  }
  
  // Verifica se API Key existe
  if (!config.apiKey) {
    console.error(`❌ API Key não configurada para: ${usuario}`);
    return {
      ...config,
      error: `API Key não configurada para ${usuario}`
    };
  }
  
  // Verifica se Instance Name existe
  if (!config.instanceName) {
    console.error(`❌ Instance Name não configurado para: ${usuario}`);
    return {
      ...config,
      error: `Instance Name não configurado para ${usuario}`
    };
  }
  
  console.log(`✅ Config carregada para ${usuario}: ${config.instanceName} (API: ***${config.apiKey.slice(-4)})`);
  return config;
}

// ========== MIDDLEWARES ==========
const allowedOrigins = process.env.ALLOWED_ORIGINS ? 
  process.env.ALLOWED_ORIGINS.split(',') : 
  [];

app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Requested-With']
}));

app.set('trust proxy', 1);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('.'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'segredo-muito-secreto-2025',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false, 
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true
  }
}));

// ========== SISTEMA DE AUTENTICAÇÃO ==========
function parseUsuarios() {
  const usuarios = {};
  const usuariosEnv = process.env.USUARIOS || 'admin:admin123';
  
  usuariosEnv.split(',').forEach(credencial => {
    const [usuario, senha] = credencial.split(':');
    if (usuario && senha) {
      usuarios[usuario.trim()] = senha.trim();
    }
  });
  
  return usuarios;
}

const usuarios = parseUsuarios();
console.log('👥 Usuários carregados:', Object.keys(usuarios));

// Middleware de autenticação
function requireAuth(req, res, next) {
  if (req.session && req.session.usuario) {
    console.log('🔐 Usuário autenticado:', req.session.usuario);
    next();
  } else {
    console.log('❌ Acesso não autorizado');
    res.status(401).json({ error: 'Não autenticado' });
  }
}

// ========== ROTAS DE AUTENTICAÇÃO ==========
app.post('/api/login', express.json(), (req, res) => {
  const { usuario, senha } = req.body;
  
  console.log('🔐 Tentativa de login:', usuario);
  
  if (usuarios[usuario] && usuarios[usuario] === senha) {
    req.session.usuario = usuario;
    req.session.save((err) => {
      if (err) {
        console.error('❌ Erro ao salvar sessão:', err);
        return res.status(500).json({ success: false, error: 'Erro interno' });
      }
      
      const userConfig = getEvolutionConfigByUser(usuario);
      console.log('✅ Login bem-sucedido para:', usuario);
      
      res.json({ 
        success: true, 
        usuario: usuario,
        config: userConfig
      });
    });
  } else {
    console.log('❌ Credenciais inválidas para:', usuario);
    res.status(401).json({ success: false, error: 'Credenciais inválidas' });
  }
});

app.post('/api/logout', (req, res) => {
  const usuario = req.session.usuario;
  req.session.destroy((err) => {
    if (err) {
      console.error('❌ Erro ao fazer logout:', err);
      return res.status(500).json({ success: false, error: 'Erro interno' });
    }
    console.log('🚪 Logout do usuário:', usuario);
    res.json({ success: true });
  });
});

app.get('/api/auth/status', (req, res) => {
  const autenticado = !!(req.session && req.session.usuario);
  const userConfig = autenticado ? getEvolutionConfigByUser(req.session.usuario) : null;
  
  res.json({ 
    autenticado: autenticado,
    usuario: req.session?.usuario,
    config: userConfig
  });
});

// ========== BANCO DE DADOS ==========
const db = new sqlite3.Database('./contatos.db', (err) => {
  if (err) {
    console.error('❌ Erro no banco:', err);
  } else {
    console.log('✅ SQLite conectado');
  }
});

// Criar tabela com melhor tratamento de erro
db.run(`CREATE TABLE IF NOT EXISTS contatos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  number TEXT NOT NULL,
  category TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(name, number)
)`, (err) => {
  if (err) {
    console.error('❌ Erro ao criar tabela:', err);
  } else {
    console.log('✅ Tabela contatos verificada/criada');
  }
});

// ========== FUNÇÕES AUXILIARES ==========
function formatNumberForEvolution(number) {
  let cleanNumber = number.replace(/\D/g, '');
  if (!cleanNumber.startsWith('55')) {
    cleanNumber = '55' + cleanNumber;
  }
  return cleanNumber + '@c.us';
}

function isValidApiConfig(config) {
  return config && config.apiKey && config.instanceName && !config.error;
}

// ========== ROTAS PÚBLICAS ==========
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/index.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ========== ROTAS PROTEGIDAS ==========
app.get('/painel.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'painel.html'));
});

app.get('/contatos.csv', requireAuth, (req, res) => {
  const csvPath = path.join(__dirname, 'contatos.csv');
  if (!fs.existsSync(csvPath)) {
    return res.status(404).json({ error: 'Arquivo contatos.csv não encontrado' });
  }
  res.sendFile(csvPath);
});

// ========== ROTAS DA API ==========

// 📊 Informações do usuário logado
app.get('/api/user/info', requireAuth, (req, res) => {
  const userConfig = getEvolutionConfigByUser(req.session.usuario);
  
  if (!isValidApiConfig(userConfig)) {
    return res.status(500).json({
      error: 'Configuração incompleta',
      details: userConfig.error,
      usuario: req.session.usuario
    });
  }
  
  res.json({
    usuario: req.session.usuario,
    config: userConfig,
    instancia: userConfig.instanceName,
    baseUrl: EVOLUTION_CONFIG.baseUrl
  });
});

// ========== ROTAS DE UPLOAD DE CSV ==========

// 📤 Upload de arquivo CSV via FormData (NOVA ROTA)
app.post('/api/upload-csv-file', requireAuth, upload.single('csvFile'), async (req, res) => {
  console.log('📤 Recebendo upload de arquivo CSV por:', req.session.usuario);
  
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'Nenhum arquivo enviado'
      });
    }

    console.log('📁 Arquivo recebido:', req.file.originalname, req.file.size, 'bytes');

    const contatos = [];
    let processed = 0;
    let errors = 0;

    // Ler e processar o CSV
    fs.createReadStream(req.file.path)
      .pipe(csv({
        mapHeaders: ({ header, index }) => header.trim().toLowerCase(),
        separator: ','
      }))
      .on('data', (row) => {
        try {
          processed++;
          
          // Mapear colunas do CSV (flexível para diferentes formatos)
          const name = row.nome || row.name || row['nome completo'] || '';
          const number = (row.telefone || row.number || row.celular || row.phone || '').toString().replace(/\D/g, '');
          const category = row.categoria || row.category || row.tipo || 'sider';
          
          if (name && number && number.length >= 10) {
            contatos.push({
              name: name.trim(),
              number: number,
              category: category.trim().toLowerCase()
            });
          } else {
            console.log('❌ Dados inválidos ou incompletos:', { name, number: number || 'vazio' });
            errors++;
          }
        } catch (err) {
          console.error('❌ Erro ao processar linha:', err);
          errors++;
        }
      })
      .on('end', async () => {
        try {
          // Limpar arquivo temporário
          fs.unlinkSync(req.file.path);
          
          console.log(`📊 CSV processado: ${processed} linhas, ${contatos.length} válidos, ${errors} erros`);
          
          if (contatos.length === 0) {
            return res.json({ 
              success: false, 
              error: 'Nenhum contato válido encontrado no arquivo. Verifique o formato do CSV.' 
            });
          }

          // Salvar contatos no banco
          let inserted = 0;
          let duplicateErrors = 0;

          // Usar transação
          db.serialize(() => {
            db.run('BEGIN TRANSACTION');
            
            const stmt = db.prepare('INSERT OR IGNORE INTO contatos (name, number, category) VALUES (?, ?, ?)');
            
            contatos.forEach((contact, index) => {
              stmt.run([contact.name, contact.number, contact.category], function(err) {
                if (err) {
                  console.error('❌ Erro DB:', err);
                  duplicateErrors++;
                } else {
                  if (this.changes > 0) {
                    inserted++;
                  } else {
                    duplicateErrors++;
                  }
                }
                
                // Último contato
                if (index === contatos.length - 1) {
                  stmt.finalize((err) => {
                    if (err) {
                      db.run('ROLLBACK');
                      console.error('❌ Erro ao finalizar statement:', err);
                      return res.status(500).json({ 
                        success: false, 
                        error: 'Erro ao salvar no banco de dados' 
                      });
                    }
                    
                    db.run('COMMIT', (err) => {
                      if (err) {
                        console.error('❌ Erro no commit:', err);
                        return res.status(500).json({ 
                          success: false, 
                          error: 'Erro ao confirmar transação' 
                        });
                      }
                      
                      console.log(`✅ Importação concluída: ${inserted} inseridos, ${duplicateErrors} duplicados/erros`);
                      
                      res.json({
                        success: true,
                        message: 'CSV importado com sucesso!',
                        total: contatos.length,
                        processed: processed,
                        inserted: inserted,
                        duplicates: duplicateErrors,
                        errors: errors,
                        usuario: req.session.usuario
                      });
                    });
                  });
                }
              });
            });
          });

        } catch (finalErr) {
          console.error('❌ Erro final:', finalErr);
          res.status(500).json({ 
            success: false, 
            error: 'Erro ao processar arquivo CSV' 
          });
        }
      })
      .on('error', (err) => {
        console.error('❌ Erro ao ler CSV:', err);
        // Limpar arquivo em caso de erro
        if (fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ 
          success: false, 
          error: 'Erro ao ler arquivo CSV. Verifique o formato.' 
        });
      });

  } catch (error) {
    console.error('❌ Erro no upload:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Erro interno do servidor' 
    });
  }
});

// 🔄 Importar CSV do arquivo local (se existir)
app.get('/webhook/importar-csv', requireAuth, async (req, res) => {
  console.log('🔄 Importando CSV existente por:', req.session.usuario);
  
  try {
    const csvPath = path.join(__dirname, 'contatos.csv');
    
    if (!fs.existsSync(csvPath)) {
      return res.status(404).json({ 
        success: false, 
        error: 'Arquivo contatos.csv não encontrado. Faça upload primeiro.' 
      });
    }
    
    const csvText = fs.readFileSync(csvPath, 'utf8');
    const lines = csvText.split('\n').filter(line => line.trim());
    
    const contatos = [];
    const header = lines[0].toLowerCase();
    const hasHeader = header.includes('nome') || header.includes('name');
    const startLine = hasHeader ? 1 : 0;

    for (let i = startLine; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      
      const parts = line.split(',').length >= 2 ? 
        line.split(',') : line.split(';');
      
      if (parts.length >= 2) {
        const name = parts[0].trim();
        const number = parts[1].trim().replace(/\D/g, '');
        const category = parts[2] ? parts[2].trim() : 'sider';
        
        if (name && number && number.length >= 10) {
          contatos.push({ name, number, category });
        }
      }
    }
    
    if (contatos.length === 0) {
      return res.json({ 
        success: false, 
        error: 'Nenhum contato válido encontrado no CSV' 
      });
    }
    
    console.log(`📄 ${req.session.usuario} importando ${contatos.length} contatos`);
    
    // Usar transação para melhor performance
    db.serialize(() => {
      db.run('BEGIN TRANSACTION');
      
      db.run('DELETE FROM contatos', function(err) {
        if (err) {
          db.run('ROLLBACK');
          console.error('❌ Erro ao limpar contatos:', err);
          return res.status(500).json({ 
            success: false, 
            error: 'Erro ao limpar contatos antigos' 
          });
        }
        
        console.log(`🗑️ Contatos antigos removidos: ${this.changes}`);
        
        const stmt = db.prepare('INSERT OR IGNORE INTO contatos (name, number, category) VALUES (?, ?, ?)');
        let inseridos = 0;
        let duplicados = 0;

        contatos.forEach((contato, index) => {
          stmt.run([contato.name, contato.number, contato.category], function(err) {
            if (err) {
              console.error('❌ Erro ao inserir:', err);
              duplicados++;
            } else {
              if (this.changes > 0) {
                inseridos++;
              } else {
                duplicados++;
              }
            }
            
            if (index === contatos.length - 1) {
              stmt.finalize((err) => {
                if (err) {
                  db.run('ROLLBACK');
                  console.error('❌ Erro ao finalizar statement:', err);
                  return res.status(500).json({ 
                    success: false, 
                    error: 'Erro na importação' 
                  });
                }
                
                db.run('COMMIT', (err) => {
                  if (err) {
                    console.error('❌ Erro no commit:', err);
                    return res.status(500).json({ 
                      success: false, 
                      error: 'Erro ao salvar dados' 
                    });
                  }
                  
                  console.log(`📊 Importação concluída: ${inseridos} inseridos, ${duplicados} duplicados/erros`);
                  
                  res.json({
                    success: true,
                    message: 'CSV importado com sucesso',
                    total: contatos.length,
                    inseridos: inseridos,
                    duplicados: duplicados,
                    usuario: req.session.usuario
                  });
                });
              });
            }
          });
        });
      });
    });
    
  } catch (error) {
    console.error('❌ Erro ao importar CSV:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno ao importar CSV: ' + error.message
    });
  }
});

// 📡 Status da Evolution
app.get('/webhook/status-evolution', requireAuth, async (req, res) => {
  const userConfig = getEvolutionConfigByUser(req.session.usuario);
  
  console.log('🔍 Testando conexão para:', req.session.usuario);
  console.log('🏷️ Instância:', userConfig.instanceName);
  console.log('🔑 API Key:', userConfig.apiKey ? '***' + userConfig.apiKey.slice(-4) : 'NÃO CONFIGURADA');
  
  if (!isValidApiConfig(userConfig)) {
    return res.status(500).json({
      connected: false,
      error: 'Configuração incompleta',
      message: userConfig.error,
      usuario: req.session.usuario
    });
  }
  
  try {
    // Testar conexão básica com Evolution
    const response = await fetch(EVOLUTION_CONFIG.baseUrl, {
      timeout: 10000
    });

    if (!response.ok) {
      return res.status(500).json({
        connected: false,
        error: `HTTP ${response.status}`,
        message: 'Evolution não está respondendo',
        usuario: req.session.usuario,
        instancia: userConfig.instanceName
      });
    }

    // Testar autenticação com API Key
    const authResponse = await fetch(`${EVOLUTION_CONFIG.baseUrl}/instance/fetchInstances`, {
      headers: {
        'apikey': userConfig.apiKey,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });

    if (authResponse.ok) {
      const instances = await authResponse.json();
      const instanceExists = Array.isArray(instances) ? 
        instances.some(inst => 
          inst.instanceName === userConfig.instanceName || 
          inst.id === userConfig.instanceName
        ) : false;

      res.json({
        connected: true,
        message: '✅ Evolution conectado!',
        instance: instanceExists ? 'Encontrada' : 'Não encontrada',
        instanceName: userConfig.instanceName,
        usuario: req.session.usuario,
        instancesCount: Array.isArray(instances) ? instances.length : 0
      });
      
    } else if (authResponse.status === 401) {
      res.status(500).json({
        connected: false,
        error: 'API Key inválida',
        message: 'Verifique a API Key no Evolution Manager',
        usuario: req.session.usuario,
        instancia: userConfig.instanceName
      });
    } else {
      const errorText = await authResponse.text();
      res.status(500).json({
        connected: false,
        error: `Erro ${authResponse.status}`,
        message: 'Problema na configuração da API',
        details: errorText,
        usuario: req.session.usuario
      });
    }
    
  } catch (error) {
    console.error('❌ Erro na conexão:', error.message);
    res.status(500).json({
      connected: false,
      error: 'Falha na conexão',
      message: 'Verifique: IP, Docker, Rede, Firewall',
      details: error.message,
      usuario: req.session.usuario
    });
  }
});

// 📤 Envio de mensagens
app.post('/webhook/send', requireAuth, async (req, res) => {
  const { number, message } = req.body;
  const usuario = req.session.usuario;
  const userConfig = getEvolutionConfigByUser(usuario);
  
  console.log('📤 Tentando enviar mensagem:');
  console.log('👤 Usuário:', usuario);
  console.log('🔢 Número:', number);
  console.log('🏷️ Instância:', userConfig.instanceName);
  console.log('🔑 API Key:', userConfig.apiKey ? '***' + userConfig.apiKey.slice(-4) : 'NÃO CONFIGURADA');
  
  // Validação da configuração
  if (!isValidApiConfig(userConfig)) {
    return res.status(500).json({ 
      success: false, 
      error: `❌ Configuração incompleta para ${usuario}`,
      details: userConfig.error
    });
  }
  
  // Validações básicas
  if (!number || !message) {
    return res.status(400).json({ 
      success: false, 
      error: 'Número e mensagem são obrigatórios' 
    });
  }
  
  try {
    const formattedNumber = formatNumberForEvolution(number);
    console.log('🔢 Número formatado:', formattedNumber);
    
    const url = `${EVOLUTION_CONFIG.baseUrl}/message/sendText/${userConfig.instanceName}`;
    console.log('🌐 URL da requisição:', url);
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': userConfig.apiKey
      },
      body: JSON.stringify({
        number: formattedNumber,
        text: message
      }),
      timeout: 30000
    });
    
    console.log('📡 Status da Evolution:', response.status);
    
    if (response.ok) {
      const result = await response.json();
      console.log('✅ Mensagem enviada com sucesso:', result);
      
      res.json({ 
        success: true, 
        message: '✅ Mensagem enviada com sucesso!',
        usuario: usuario,
        instancia: userConfig.instanceName,
        messageId: result.key?.id
      });
    } else if (response.status === 404) {
      console.log('❌ Instância não encontrada');
      res.status(500).json({ 
        success: false, 
        error: '❌ Instância não encontrada',
        details: `A instância "${userConfig.instanceName}" não existe no Evolution`,
        solution: 'Verifique o nome da instância no Evolution Manager'
      });
    } else if (response.status === 401) {
      console.log('❌ API Key inválida');
      res.status(500).json({ 
        success: false, 
        error: '❌ API Key inválida',
        details: 'A API Key não é válida para esta instância',
        solution: 'Verifique a API Key no Evolution Manager'
      });
    } else {
      const errorText = await response.text();
      console.log('❌ Erro da Evolution:', errorText);
      res.status(500).json({ 
        success: false, 
        error: `❌ Erro ${response.status} do Evolution`,
        details: errorText
      });
    }
    
  } catch (error) {
    console.log('❌ Erro de conexão:', error.message);
    res.status(500).json({ 
      success: false, 
      error: '❌ Erro de comunicação com o Evolution',
      details: error.message,
      solution: 'Verifique se o Evolution está rodando e acessível'
    });
  }
});

// 👥 Gerenciar contatos
app.get('/webhook/contatos', requireAuth, (req, res) => {
  const categoria = req.query.categoria;
  if (!categoria) {
    return res.status(400).json({ error: 'Parâmetro categoria é necessário' });
  }

  db.all('SELECT id, name, number, category FROM contatos WHERE category = ? ORDER BY name', 
    [categoria], (err, rows) => {
    if (err) {
      console.error('❌ Erro ao buscar contatos:', err);
      res.status(500).json({ error: err.message });
    } else {
      res.json(rows);
    }
  });
});

// 📊 Listar todas as categorias
app.get('/webhook/categorias', requireAuth, (req, res) => {
  db.all('SELECT DISTINCT category FROM contatos ORDER BY category', (err, rows) => {
    if (err) {
      console.error('❌ Erro ao buscar categorias:', err);
      res.status(500).json({ error: err.message });
    } else {
      const categorias = rows.map(row => row.category);
      res.json(categorias);
    }
  });
});

app.post('/webhook/contatos', requireAuth, (req, res) => {
  const { name, number, category } = req.body;
  if (!name || !number || !category) {
    return res.status(400).json({ error: 'Nome, número e categoria são obrigatórios' });
  }

  db.run('INSERT OR IGNORE INTO contatos (name, number, category) VALUES (?, ?, ?)',
    [name, number, category], function(err) {
    if (err) {
      console.error('❌ Erro ao adicionar contato:', err);
      res.status(500).json({ error: err.message });
    } else {
      if (this.changes > 0) {
        res.json({ id: this.lastID, message: 'Contato adicionado com sucesso' });
      } else {
        res.status(409).json({ error: 'Contato já existe' });
      }
    }
  });
});

// 🗑️ Deletar contato
app.delete('/webhook/contatos/:id', requireAuth, (req, res) => {
  const contactId = req.params.id;
  console.log('🗑️ Tentando excluir contato ID:', contactId);
  
  db.run('DELETE FROM contatos WHERE id = ?', [contactId], function(err) {
    if (err) {
      console.error('❌ Erro ao excluir:', err);
      res.status(500).json({ error: err.message });
    } else {
      console.log('✅ Contato excluído, changes:', this.changes);
      if (this.changes > 0) {
        res.json({ message: 'Contato excluído com sucesso' });
      } else {
        res.status(404).json({ error: 'Contato não encontrado' });
      }
    }
  });
});

// 🧹 Limpar todos os contatos
app.delete('/webhook/limpar-contatos', requireAuth, (req, res) => {
  console.log('🗑️ Limpando TODOS os contatos do banco...');
  
  db.run('DELETE FROM contatos', function(err) {
    if (err) {
      console.error('❌ Erro ao limpar contatos:', err);
      res.status(500).json({ error: err.message });
    } else {
      console.log('✅ Contatos apagados:', this.changes);
      res.json({ 
        success: true,
        message: 'Todos os contatos foram apagados',
        contatos_apagados: this.changes
      });
    }
  });
});

// ========== ROTAS DE DEBUG E TESTE ==========
app.get('/test', (req, res) => {
  res.json({ 
    message: '🚀 Sistema funcionando!',
    port: PORT,
    usuarios: Object.keys(usuarios),
    evolution_url: EVOLUTION_CONFIG.baseUrl,
    timestamp: new Date().toISOString()
  });
});

app.get('/api/debug/usuarios', (req, res) => {
  res.json({
    usuarios_carregados: Object.keys(usuarios),
    total_usuarios: Object.keys(usuarios).length,
    variavel_env: process.env.USUARIOS
  });
});

// 🔧 Testar configurações de API
app.get('/api/debug/config', requireAuth, (req, res) => {
  const users = ['admin', 'JBO', 'CABO'];
  const configs = {};
  
  users.forEach(user => {
    configs[user] = getEvolutionConfigByUser(user);
  });
  
  res.json({
    evolutionBaseUrl: EVOLUTION_CONFIG.baseUrl,
    configs: configs
  });
});

// ========== HEALTH CHECK ==========
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    evolution: EVOLUTION_CONFIG.baseUrl
  });
});

// ========== MIDDLEWARE DE ERRO ==========
app.use((err, req, res, next) => {
  console.error('❌ Erro não tratado:', err);
  res.status(500).json({ 
    error: 'Erro interno do servidor',
    details: process.env.DEBUG_MODE ? err.message : 'Contate o administrador'
  });
});

// ========== ROTA 404 ==========
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Rota não encontrada',
    path: req.originalUrl
  });
});

// ========== INICIALIZAÇÃO DO SERVIDOR ==========
app.listen(PORT, '0.0.0.0', () => {
  console.log('================================');
  console.log('🎯 Servidor rodando!');
  console.log(`📍 Local: http://localhost:${PORT}`);
  console.log(`🌐 Externo: http://SEU-IP:${PORT}`);
  console.log(`🐳 Evolution: ${EVOLUTION_CONFIG.baseUrl}`);
  console.log(`🔐 Login ativo: ${Object.keys(usuarios).join(', ')}`);
  console.log('================================');
  
  // Verificar configurações dos usuários
  Object.keys(usuarios).forEach(usuario => {
    const config = getEvolutionConfigByUser(usuario);
    if (config.error) {
      console.log(`⚠️  ${usuario}: ${config.error}`);
    } else {
      console.log(`✅ ${usuario}: ${config.instanceName} (API: ***${config.apiKey.slice(-4)})`);
    }
  });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('🔄 Encerrando servidor...');
  db.close((err) => {
    if (err) {
      console.error('❌ Erro ao fechar banco:', err);
    } else {
      console.log('✅ Banco de dados fechado');
    }
    process.exit(0);
  });
});