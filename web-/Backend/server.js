const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();

// Configurar CORS para o frontend correto
app.use(cors({
  origin: 'https://web-frontend-p17n.onrender.com' // Corrigido para o domínio atual do frontend
}));
app.use(express.json());

// Conexão com MongoDB com opções modernas
mongoose.connect(process.env.MONGODB_URI, {
  retryWrites: true,
  maxPoolSize: 10 // Ajuste conforme necessário
})
  .then(() => console.log('Mongoose conectado ao MongoDB'))
  .catch((err) => console.error('Erro de conexão com MongoDB:', err.message));

// Modelos
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'moderator', 'admin'], default: 'user' },
  depositsToday: { type: Number, default: 0 },
  totalDeposits: { type: Number, default: 0 },
  linkedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  linkedDeposits: { type: Number, default: 0 },
  suspended: { type: Boolean, default: false },
  banned: { type: Boolean, default: false },
  totalAdded: { type: Number, default: 0 }, // Para moderadores
  totalRemoved: { type: Number, default: 0 } // Para moderadores
});
userSchema.index({ username: 1 }, { unique: true }); // Índice único para username

const productSchema = new mongoose.Schema({
  image: { type: String, required: true },
  name: { type: String, required: true },
  price: { type: Number, required: true },
  expiry: { type: Date, required: true } // Mudado para Date para facilitar comparações
});

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);

// Middleware para autenticação
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token não fornecido' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).lean().exec();
    if (!req.user) return res.status(401).json({ message: 'Usuário não encontrado' });
    next();
  } catch (err) {
    console.error('Erro de autenticação:', err.message);
    res.status(401).json({ message: 'Token inválido' });
  }
};

// Middleware para verificar role
const roleMiddleware = (role) => (req, res, next) => {
  if (req.user.role !== role) return res.status(403).json({ message: 'Acesso negado' });
  next();
};

// Rotas de autenticação
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username e senha são obrigatórios' });
    if (await User.findOne({ username })) return res.status(400).json({ message: 'Username já existe' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user });
  } catch (err) {
    console.error('Erro no registro:', err.message);
    res.status(500).json({ message: 'Erro ao registrar usuário' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username e senha são obrigatórios' });
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }
    if (user.banned) return res.status(403).json({ message: 'Usuário banido' });
    if (user.suspended) return res.status(403).json({ message: 'Usuário suspenso' });
    if (role && user.role !== role) return res.status(401).json({ message: 'Role inválida' }); // Validação de role
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user, role: user.role });
  } catch (err) {
    console.error('Erro no login:', err.message);
    res.status(500).json({ message: 'Erro ao fazer login' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    res.json({ user: req.user, role: req.user.role });
  } catch (err) {
    console.error('Erro ao recuperar usuário:', err.message);
    res.status(500).json({ message: 'Erro ao recuperar dados do usuário' });
  }
});

// Rotas de usuários
app.get('/api/users', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  try {
    const users = await User.find({ role: 'user' });
    res.json(users);
  } catch (err) {
    console.error('Erro ao listar usuários:', err.message);
    res.status(500).json({ message: 'Erro ao listar usuários' });
  }
});

app.put('/api/users/:id/suspend', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'Usuário não encontrado' });
    user.suspended = !user.suspended;
    await user.save();
    res.json(user);
  } catch (err) {
    console.error('Erro ao suspender usuário:', err.message);
    res.status(500).json({ message: 'Erro ao suspender usuário' });
  }
});

app.put('/api/users/:id/ban', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'Usuário não encontrado' });
    user.banned = !user.banned;
    await user.save();
    res.json(user);
  } catch (err) {
    console.error('Erro ao banir usuário:', err.message);
    res.status(500).json({ message: 'Erro ao banir usuário' });
  }
});

// Rotas de moderadores
app.get('/api/moderators', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  try {
    const moderators = await User.find({ role: 'moderator' });
    res.json(moderators);
  } catch (err) {
    console.error('Erro ao listar moderadores:', err.message);
    res.status(500).json({ message: 'Erro ao listar moderadores' });
  }
});

app.post('/api/moderators', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username e senha são obrigatórios' });
    if (await User.findOne({ username })) return res.status(400).json({ message: 'Username já existe' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const moderator = new User({ username, password: hashedPassword, role: 'moderator' });
    await moderator.save();
    res.json(moderator);
  } catch (err) {
    console.error('Erro ao criar moderador:', err.message);
    res.status(500).json({ message: 'Erro ao criar moderador' });
  }
});

app.put('/api/moderators/:id/suspend', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  try {
    const moderator = await User.findById(req.params.id);
    if (!moderator) return res.status(404).json({ message: 'Moderador não encontrado' });
    moderator.suspended = !moderator.suspended;
    await moderator.save();
    res.json(moderator);
  } catch (err) {
    console.error('Erro ao suspender moderador:', err.message);
    res.status(500).json({ message: 'Erro ao suspender moderador' });
  }
});

app.put('/api/moderators/:id/ban', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  try {
    const moderator = await User.findById(req.params.id);
    if (!moderator) return res.status(404).json({ message: 'Moderador não encontrado' });
    moderator.banned = !moderator.banned;
    await moderator.save();
    res.json(moderator);
  } catch (err) {
    console.error('Erro ao banir moderador:', err.message);
    res.status(500).json({ message: 'Erro ao banir moderador' });
  }
});

// Rotas de produtos
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    console.error('Erro ao listar produtos:', err.message);
    res.status(500).json({ message: 'Erro ao listar produtos' });
  }
});

app.post('/api/products', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  try {
    const { image, name, price, expiry } = req.body;
    if (!image || !name || price < 0 || !expiry) {
      return res.status(400).json({ message: 'Dados do produto inválidos' });
    }
    const product = new Product({ image, name, price, expiry: new Date(expiry) }); // Converter para Date
    await product.save();
    res.json(product);
  } catch (err) {
    console.error('Erro ao criar produto:', err.message);
    res.status(500).json({ message: 'Erro ao criar produto' });
  }
});

// Inicializar admin padrão
async function initializeAdmin() {
  try {
    const adminExists = await User.findOne({ username: 'adminchief', role: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('adminpass', 10);
      await new User({ username: 'adminchief', password: hashedPassword, role: 'admin' }).save();
      console.log('Admin criado com sucesso');
    }
  } catch (err) {
    console.error('Erro ao inicializar admin:', err.message);
  }
}
initializeAdmin();

// Iniciar servidor
const PORT = process.env.PORT; // Remover fallback para 3000
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
