const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Conexão com MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

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

const productSchema = new mongoose.Schema({
  image: { type: String, required: true },
  name: { type: String, required: true },
  price: { type: Number, required: true },
  expiry: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);

// Middleware para autenticação
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token não fornecido' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user) return res.status(401).json({ message: 'Usuário não encontrado' });
    next();
  } catch (err) {
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
  const { username, password } = req.body;
  if (await User.findOne({ username })) return res.status(400).json({ message: 'Username já existe' });
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword });
  await user.save();
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, user });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password, role } = req.body;
  const user = await User.findOne({ username, role });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: 'Credenciais inválidas' });
  }
  if (user.banned) return res.status(403).json({ message: 'Usuário banido' });
  if (user.suspended) return res.status(403).json({ message: 'Usuário suspenso' });
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, user, role });
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  res.json({ user: req.user, role: req.user.role });
});

// Rotas de usuários
app.get('/api/users', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  const users = await User.find({ role: 'user' });
  res.json(users);
});

app.put('/api/users/:id/suspend', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ message: 'Usuário não encontrado' });
  user.suspended = !user.suspended;
  await user.save();
  res.json(user);
});

app.put('/api/users/:id/ban', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ message: 'Usuário não encontrado' });
  user.banned = !user.banned;
  await user.save();
  res.json(user);
});

// Rotas de moderadores
app.get('/api/moderators', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  const moderators = await User.find({ role: 'moderator' });
  res.json(moderators);
});

app.post('/api/moderators', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  const { username, password } = req.body;
  if (await User.findOne({ username })) return res.status(400).json({ message: 'Username já existe' });
  const hashedPassword = await bcrypt.hash(password, 10);
  const moderator = new User({ username, password: hashedPassword, role: 'moderator' });
  await moderator.save();
  res.json(moderator);
});

app.put('/api/moderators/:id/suspend', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  const moderator = await User.findById(req.params.id);
  if (!moderator) return res.status(404).json({ message: 'Moderador não encontrado' });
  moderator.suspended = !moderator.suspended;
  await moderator.save();
  res.json(moderator);
});

app.put('/api/moderators/:id/ban', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  const moderator = await User.findById(req.params.id);
  if (!moderator) return res.status(404).json({ message: 'Moderador não encontrado' });
  moderator.banned = !moderator.banned;
  await moderator.save();
  res.json(moderator);
});

// Rotas de produtos
app.get('/api/products', async (req, res) => {
  const products = await Product.find();
  res.json(products);
});

app.post('/api/products', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  const product = new Product(req.body);
  await product.save();
  res.json(product);
});

// Inicializar admin padrão
async function initializeAdmin() {
  const adminExists = await User.findOne({ username: 'adminchief', role: 'admin' });
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash('adminpass', 10);
    await new User({ username: 'adminchief', password: hashedPassword, role: 'admin' }).save();
  }
}
initializeAdmin();

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});