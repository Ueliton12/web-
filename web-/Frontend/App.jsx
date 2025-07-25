const React = window.React;
const { useState, useEffect } = React;
const ReactDOM = window.ReactDOM;
const axios = window.axios;

const App = () => {
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 768);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentPage, setCurrentPage] = useState('user-login');
  const [fadeOut, setFadeOut] = useState(false);
  const [user, setUser] = useState(null);
  const [moderator, setModerator] = useState(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [isModerator, setIsModerator] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedUser, setSelectedUser] = useState(null);
  const [selectedModerator, setSelectedModerator] = useState(null);
  const [products, setProducts] = useState([]);

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth <= 768);
    window.addEventListener('resize', handleResize);
    const urlParams = new URLSearchParams(window.location.search);
    const role = urlParams.get('role');
    if (role === 'admin') setCurrentPage('admin-login');
    else if (role === 'moderator') setCurrentPage('moderator-login');

    // Carregar produtos
    axios.get(`${process.env.REACT_APP_API_URL}/api/products`)
      .then(res => setProducts(res.data))
      .catch(err => console.error('Erro ao carregar produtos:', err));

    // Verificar autenticação
    const token = localStorage.getItem('token');
    if (token) {
      axios.get(`${process.env.REACT_APP_API_URL}/api/auth/me`, { headers: { Authorization: `Bearer ${token}` } })
        .then(res => {
          const { role, user } = res.data;
          setIsAuthenticated(true);
          if (role === 'user') {
            setUser(user);
            setCurrentPage('home');
          } else if (role === 'moderator') {
            setModerator(user);
            setIsModerator(true);
            setCurrentPage('moderator-dashboard');
          } else if (role === 'admin') {
            setIsAdmin(true);
            setCurrentPage('admin-dashboard');
          }
        })
        .catch(err => {
          console.error('Erro ao verificar autenticação:', err);
          localStorage.removeItem('token');
        });
    }
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Autenticação
  const handleUserLogin = async (username, password) => {
    setFadeOut(true);
    try {
      const res = await axios.post(`${process.env.REACT_APP_API_URL}/api/auth/login`, { username, password, role: 'user' });
      localStorage.setItem('token', res.data.token);
      setIsAuthenticated(true);
      setUser(res.data.user);
      setCurrentPage('home');
    } catch (err) {
      alert(err.response?.data?.message || 'Erro ao fazer login');
    }
    setFadeOut(false);
  };

  const handleUserRegister = async (username, password) => {
    setFadeOut(true);
    try {
      await axios.post(`${process.env.REACT_APP_API_URL}/api/auth/register`, { username, password });
      await handleUserLogin(username, password);
    } catch (err) {
      alert(err.response?.data?.message || 'Erro ao registrar');
    }
    setFadeOut(false);
  };

  const handleAdminLogin = async (username, password) => {
    setFadeOut(true);
    try {
      const res = await axios.post(`${process.env.REACT_APP_API_URL}/api/auth/login`, { username, password, role: 'admin' });
      localStorage.setItem('token', res.data.token);
      setIsAdmin(true);
      setCurrentPage('admin-dashboard');
    } catch (err) {
      alert(err.response?.data?.message || 'Erro ao fazer login');
    }
    setFadeOut(false);
  };

  const handleModeratorLogin = async (username, password) => {
    setFadeOut(true);
    try {
      const res = await axios.post(`${process.env.REACT_APP_API_URL}/api/auth/login`, { username, password, role: 'moderator' });
      localStorage.setItem('token', res.data.token);
      setIsModerator(true);
      setModerator(res.data.user);
      setCurrentPage('moderator-dashboard');
    } catch (err) {
      alert(err.response?.data?.message || 'Erro ao fazer login');
    }
    setFadeOut(false);
  };

  // Funções Admin
  const addModerator = async (username, password) => {
    try {
      await axios.post(`${process.env.REACT_APP_API_URL}/api/moderators`, { username, password }, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      alert('Moderador adicionado!');
    } catch (err) {
      alert(err.response?.data?.message || 'Erro ao adicionar moderador');
    }
  };

  const addProduct = async (image, name, price, expiry) => {
    try {
      const newProduct = { image, name, price, expiry };
      const res = await axios.post(`${process.env.REACT_APP_API_URL}/api/products`, newProduct, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      setProducts([...products, res.data]);
      alert('Produto adicionado!');
    } catch (err) {
      alert(err.response?.data?.message || 'Erro ao adicionar produto');
    }
  };

  const toggleSuspendModerator = async (id) => {
    try {
      await axios.put(`${process.env.REACT_APP_API_URL}/api/moderators/${id}/suspend`, {}, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      alert('Status do moderador atualizado!');
    } catch (err) {
      alert(err.response?.data?.message || 'Erro ao atualizar moderador');
    }
  };

  const toggleBanModerator = async (id) => {
    try {
      await axios.put(`${process.env.REACT_APP_API_URL}/api/moderators/${id}/ban`, {}, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      alert('Status do moderador atualizado!');
    } catch (err) {
      alert(err.response?.data?.message || 'Erro ao atualizar moderador');
    }
  };

  const toggleSuspendUser = async (id) => {
    try {
      await axios.put(`${process.env.REACT_APP_API_URL}/api/users/${id}/suspend`, {}, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      alert('Status do usuário atualizado!');
    } catch (err) {
      alert(err.response?.data?.message || 'Erro ao atualizar usuário');
    }
  };

  const toggleBanUser = async (id) => {
    try {
      await axios.put(`${process.env.REACT_APP_API_URL}/api/users/${id}/ban`, {}, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      alert('Status do usuário atualizado!');
    } catch (err) {
      alert(err.response?.data?.message || 'Erro ao atualizar usuário');
    }
  };

  // Componentes de Login/Register
  const UserLoginRegister = () => {
    const [isLogin, setIsLogin] = useState(true);
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleSubmit = async (e) => {
      e.preventDefault();
      if (isLogin) {
        await handleUserLogin(username, password);
      } else {
        await handleUserRegister(username, password);
      }
    };

    return (
      <div className={`flex items-center justify-center min-h-screen transition-opacity duration-2000 ${fadeOut ? 'opacity-0' : 'opacity-100'}`}>
        <div className="bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md">
          <h2 className="text-2xl font-bold mb-6 text-center">{isLogin ? 'User Login' : 'User Register'}</h2>
          <div>
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">Username</label>
              <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="w-full p-2 bg-gray-700 rounded" required />
            </div>
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full p-2 bg-gray-700 rounded" required />
            </div>
            <button onClick={handleSubmit} className="w-full bg-blue-600 p-2 rounded hover:bg-blue-700">{isLogin ? 'Login' : 'Register'}</button>
          </div>
          <button onClick={() => setIsLogin(!isLogin)} className="mt-4 text-blue-400 hover:underline">
            {isLogin ? 'Need an account? Register' : 'Already have an account? Login'}
          </button>
        </div>
      </div>
    );
  };

  const AdminLogin = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleSubmit = async (e) => {
      e.preventDefault();
      await handleAdminLogin(username, password);
    };

    return (
      <div className={`flex items-center justify-center min-h-screen transition-opacity duration-2000 ${fadeOut ? 'opacity-0' : 'opacity-100'}`}>
        <div className="bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md">
          <h2 className="text-2xl font-bold mb-6 text-center">Admin Login</h2>
          <div>
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">Username</label>
              <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="w-full p-2 bg-gray-700 rounded" required />
            </div>
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full p-2 bg-gray-700 rounded" required />
            </div>
            <button onClick={handleSubmit} className="w-full bg-blue-600 p-2 rounded hover:bg-blue-700">Login</button>
          </div>
        </div>
      </div>
    );
  };

  const ModeratorLogin = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleSubmit = async (e) => {
      e.preventDefault();
      await handleModeratorLogin(username, password);
    };

    return (
      <div className={`flex items-center justify-center min-h-screen transition-opacity duration-2000 ${fadeOut ? 'opacity-0' : 'opacity-100'}`}>
        <div className="bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md">
          <h2 className="text-2xl font-bold mb-6 text-center">Moderator Login</h2>
          <div>
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">Username</label>
              <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="w-full p-2 bg-gray-700 rounded" required />
            </div>
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full p-2 bg-gray-700 rounded" required />
            </div>
            <button onClick={handleSubmit} className="w-full bg-blue-600 p-2 rounded hover:bg-blue-700">Login</button>
          </div>
        </div>
      </div>
    );
  };

  const AdminDashboard = () => {
    const [users, setUsers] = useState([]);
    const [moderators, setModerators] = useState([]);

    useEffect(() => {
      axios.get(`${process.env.REACT_APP_API_URL}/api/users`, { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } })
        .then(res => setUsers(res.data))
        .catch(err => console.error('Erro ao carregar usuários:', err));
      axios.get(`${process.env.REACT_APP_API_URL}/api/moderators`, { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } })
        .then(res => setModerators(res.data))
        .catch(err => console.error('Erro ao carregar moderadores:', err));
    }, []);

    const filteredModerators = moderators.filter(m => m.username.toLowerCase().includes(searchQuery.toLowerCase()) || m.id.toString().includes(searchQuery));
    const totalUsers = users.length;
    const usersWithDeposits = users.filter(u => u.totalDeposits > 0).length;
    const totalModerators = moderators.length;
    const totalDepositsToday = users.reduce((sum, u) => sum + u.depositsToday, 0);
    const totalDeposits = users.reduce((sum, u) => sum + u.totalDeposits, 0);

    const ProductAdd = () => {
      const [image, setImage] = useState('');
      const [name, setName] = useState('');
      const [price, setPrice] = useState('');
      const [expiry, setExpiry] = useState('');

      const handleImageUpload = (e) => {
        const file = e.target.files?.[0];
        if (file) {
          const reader = new FileReader();
          reader.onload = (e) => setImage(e.target.result);
          reader.readAsDataURL(file);
        }
      };

      const handleDragOver = (e) => e.preventDefault();
      const handleDrop = (e) => {
        e.preventDefault();
        const file = e.dataTransfer.files?.[0];
        if (file) {
          const reader = new FileReader();
          reader.onload = (e) => setImage(e.target.result);
          reader.readAsDataURL(file);
        }
      };

      const handleSubmit = async (e) => {
        e.preventDefault();
        if (image && name && price && expiry) {
          await addProduct(image, name, price, expiry);
          setImage('');
          setName('');
          setPrice('');
          setExpiry('');
        } else {
          alert('Todos os campos são obrigatórios!');
        }
      };

      return (
        <div className="p-4">
          <h2 className="text-2xl font-bold mb-4">Adicionar Produto</h2>
          <div>
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">Imagem</label>
              <button onClick={() => setImage(`https://via.placeholder.com/150?img=${Math.floor(Math.random() * 70)}`)} className="bg-blue-600 p-2 rounded mr-2 hover:bg-blue-700">Gerar Imagem Aleatória</button>
              <input type="text" value={image} onChange={(e) => setImage(e.target.value)} placeholder="URL da Imagem" className="w-full p-2 bg-gray-700 rounded mb-2" />
              <div onDragOver={handleDragOver} onDrop={handleDrop} className="border-2 border-dashed border-gray-600 p-4 text-center mb-2">
                Arraste e solte a imagem aqui ou <input type="file" onChange={handleImageUpload} className="inline" />
              </div>
              {image && <img src={image} alt="Preview" className="w-32 h-32 object-cover mt-2" />}
            </div>
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">Nome</label>
              <input type="text" value={name} onChange={(e) => setName(e.target.value)} className="w-full p-2 bg-gray-700 rounded" required />
            </div>
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">Preço (USDT)</label>
              <input type="number" value={price} onChange={(e) => setPrice(e.target.value)} className="w-full p-2 bg-gray-700 rounded" required />
            </div>
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">Data de Expiração</label>
              <input type="date" value={expiry} onChange={(e) => setExpiry(e.target.value)} className="w-full p-2 bg-gray-700 rounded" required />
            </div>
            <button onClick={handleSubmit} className="w-full bg-blue-600 p-2 rounded hover:bg-blue-700">Adicionar Produto</button>
          </div>
        </div>
      );
    };

    return (
      <div className="min-h-screen bg-gray-900">
        {isMobile ? (
          <div className="fixed bottom-0 left-0 w-full bg-gray-800 p-4 flex justify-around">
            <button onClick={() => setCurrentPage('admin-dashboard')} className="p-2 hover:bg-gray-700 rounded">Dashboard</button>
            <button onClick={() => setCurrentPage('admin-managers')} className="p-2 hover:bg-gray-700 rounded">Gerenciadores</button>
            <button onClick={() => setCurrentPage('admin-users')} className="p-2 hover:bg-gray-700 rounded">Usuários</button>
            <button onClick={() => setCurrentPage('admin-products')} className="p-2 hover:bg-gray-700 rounded">Produtos</button>
          </div>
        ) : (
          <div className="fixed top-0 left-0 h-full w-64 bg-gray-800 p-4">
            <h2 className="text-xl font-bold mb-4">Menu Admin</h2>
            <button onClick={() => setCurrentPage('admin-dashboard')} className="block w-full text-left p-2 hover:bg-gray-700 rounded">Dashboard</button>
            <button onClick={() => setCurrentPage('admin-managers')} className="block w-full text-left p-2 hover:bg-gray-700 rounded">Gerenciadores</button>
            <button onClick={() => setCurrentPage('admin-users')} className="block w-full text-left p-2 hover:bg-gray-700 rounded">Usuários</button>
            <button onClick={() => setCurrentPage('admin-products')} className="block w-full text-left p-2 hover:bg-gray-700 rounded">Produtos</button>
          </div>
        )}
        <div className="p-4 ml-0 md:ml-64">
          {currentPage === 'admin-dashboard' && (
            <div>
              <h2 className="text-2xl font-bold mb-4">Dashboard</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-gray-800 p-4 rounded-lg"><p>Total de Usuários: {totalUsers}</p></div>
                <div className="bg-gray-800 p-4 rounded-lg"><p>Usuários com Depósitos: {usersWithDeposits}</p></div>
                <div className="bg-gray-800 p-4 rounded-lg"><p>Total de Moderadores: {totalModerators}</p></div>
                <div className="bg-gray-800 p-4 rounded-lg"><p>Depósitos Hoje: ${totalDepositsToday}</p></div>
                <div className="bg-gray-800 p-4 rounded-lg"><p>Total de Depósitos: ${totalDeposits}</p></div>
              </div>
            </div>
          )}
          {currentPage === 'admin-managers' && (
            <div>
              <h2 className="text-2xl font-bold mb-4">Gerenciadores</h2>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Pesquisar por ID ou Username"
                className="w-full p-2 mb-4 bg-gray-700 rounded"
              />
              <button onClick={() => {
                const newUsername = prompt('Digite o Username do Moderador');
                const newPassword = prompt('Digite a Senha do Moderador');
                if (newUsername && newPassword) addModerator(newUsername, newPassword);
              }} className="bg-blue-600 p-2 rounded mb-4 hover:bg-blue-700">
                Adicionar Moderador
              </button>
              {filteredModerators.map(m => (
                <div key={m.id} className="bg-gray-800 p-4 mb-2 rounded-lg">
                  <p>ID: {m.id}, Username: {m.username}</p>
                  <button onClick={() => setSelectedModerator(m)} className="bg-blue-600 p-1 rounded mr-2 hover:bg-blue-700">Ver</button>
                  <button onClick={() => toggleSuspendModerator(m.id)} className="bg-yellow-600 p-1 rounded mr-2 hover:bg-yellow-700">
                    {m.suspended ? 'Desuspender' : 'Suspender'}
                  </button>
                  <button onClick={() => toggleBanModerator(m.id)} className="bg-red-600 p-1 rounded mr-2 hover:bg-red-700">
                    {m.banned ? 'Desbanir' : 'Banir'}
                  </button>
                </div>
              ))}
              {selectedModerator && (
                <div className="mt-4 bg-gray-800 p-4 rounded-lg">
                  <h3 className="text-xl font-semibold">Perfil do Moderador</h3>
                  <p>ID: {selectedModerator.id}</p>
                  <p>Username: {selectedModerator.username}</p>
                  <p>Usuários Vinculados: {selectedModerator.linkedUsers.length}</p>
                  <p>Depósitos Totais (Vinculados): ${users.filter(u => selectedModerator.linkedUsers.includes(u.id)).reduce((sum, u) => sum + u.totalDeposits, 0)}</p>
                  <p>Depósitos Hoje (Vinculados): ${users.filter(u => selectedModerator.linkedUsers.includes(u.id)).reduce((sum, u) => sum + u.depositsToday, 0)}</p>
                  <p>Total Adicionado: ${selectedModerator.totalAdded}</p>
                  <p>Total Removido: ${selectedModerator.totalRemoved}</p>
                  <button onClick={() => setSelectedModerator(null)} className="bg-gray-600 p-2 rounded mt-2 hover:bg-gray-700">Fechar</button>
                </div>
              )}
            </div>
          )}
          {currentPage === 'admin-users' && (
            <div>
              <h2 className="text-2xl font-bold mb-4">Usuários</h2>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Pesquisar por ID ou Username"
                className="w-full p-2 mb-4 bg-gray-700 rounded"
              />
              {users.filter(u => u.username.toLowerCase().includes(searchQuery.toLowerCase()) || u.id.toString().includes(searchQuery)).map(u => (
                <div key={u.id} className="bg-gray-800 p-4 mb-2 rounded-lg">
                  <p>ID: {u.id}, Username: {u.username}</p>
                  <button onClick={() => setSelectedUser(u)} className="bg-blue-600 p-1 rounded mr-2 hover:bg-blue-700">Ver</button>
                  <button onClick={() => toggleSuspendUser(u.id)} className="bg-yellow-600 p-1 rounded mr-2 hover:bg-yellow-700">
                    {u.suspended ? 'Desuspender' : 'Suspender'}
                  </button>
                  <button onClick={() => toggleBanUser(u.id)} className="bg-red-600 p-1 rounded mr-2 hover:bg-blue-700">
                    {u.banned ? 'Desbanir' : 'Banir'}
                  </button>
                </div>
              ))}
              {selectedUser && (
                <div className="mt-4 bg-gray-800 p-4 rounded-lg">
                  <h3 className="text-xl font-semibold">Perfil do Usuário</h3>
                  <p>ID: {selectedUser.id}</p>
                  <p>Username: {selectedUser.username}</p>
                  <p>Depósitos Hoje: ${selectedUser.depositsToday}</p>
                  <p>Total de Depósitos: ${selectedUser.totalDeposits}</p>
                  <p>Usuários Vinculados: {selectedUser.linkedUsers}</p>
                  <p>Depósitos Vinculados: ${selectedUser.linkedDeposits}</p>
                  <button onClick={() => setSelectedUser(null)} className="bg-gray-600 p-2 rounded mt-2 hover:bg-gray-700">Fechar</button>
                </div>
              )}
            </div>
          )}
          {currentPage === 'admin-products' && <ProductAdd />}
        </div>
      </div>
    );
  };

  const ModeratorDashboard = () => {
    const [users, setUsers] = useState([]);

    useEffect(() => {
      axios.get(`${process.env.REACT_APP_API_URL}/api/users`, { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } })
        .then(res => setUsers(res.data.filter(u => moderator?.linkedUsers.includes(u.id))))
        .catch(err => console.error('Erro ao carregar usuários:', err));
    }, []);

    const filteredUsers = users.filter(u => u.username.toLowerCase().includes(searchQuery.toLowerCase()) || u.id.toString().includes(searchQuery));
    const totalDeposits = filteredUsers.reduce((sum, u) => sum + u.totalDeposits, 0);
    const depositsToday = filteredUsers.reduce((sum, u) => sum + u.depositsToday, 0);
    const totalLinkedUsers = filteredUsers.length;
    const usersWithDeposits = filteredUsers.filter(u => u.totalDeposits > 0).length;

    return (
      <div className="min-h-screen bg-gray-900">
        {isMobile ? (
          <div className="fixed bottom-0 left-0 w-full bg-gray-800 p-4 flex justify-around">
            <button onClick={() => setCurrentPage('moderator-dashboard')} className="p-2 hover:bg-gray-700 rounded">Dashboard</button>
            <button onClick={() => setCurrentPage('moderator-users')} className="p-2 hover:bg-gray-700 rounded">Usuários</button>
          </div>
        ) : (
          <div className="fixed top-0 left-0 h-full w-64 bg-gray-800 p-4">
            <h2 className="text-xl font-bold mb-4">Menu Moderador</h2>
            <button onClick={() => setCurrentPage('moderator-dashboard')} className="block w-full text-left p-2 hover:bg-gray-700 rounded">Dashboard</button>
            <button onClick={() => setCurrentPage('moderator-users')} className="block w-full text-left p-2 hover:bg-gray-700 rounded">Usuários</button>
          </div>
        )}
        <div className="p-4 ml-0 md:ml-64">
          {currentPage === 'moderator-dashboard' && (
            <div>
              <h2 className="text-2xl font-bold mb-4">Dashboard</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-gray-800 p-4 rounded-lg"><p>Total de Depósitos: ${totalDeposits}</p></div>
                <div className="bg-gray-800 p-4 rounded-lg"><p>Depósitos Hoje: ${depositsToday}</p></div>
                <div className="bg-gray-800 p-4 rounded-lg"><p>Total de Usuários Vinculados: ${totalLinkedUsers}</p></div>
                <div className="bg-gray-800 p-4 rounded-lg"><p>Usuários com Depósitos: ${usersWithDeposits}</p></div>
              </div>
            </div>
          )}
          {currentPage === 'moderator-users' && (
            <div>
              <h2 className="text-2xl font-bold mb-4">Usuários</h2>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Pesquisar por ID ou Username"
                className="w-full p-2 mb-4 bg-gray-700 rounded"
              />
              {filteredUsers.map(u => (
                <div key={u.id} className="bg-gray-800 p-4 mb-2 rounded-lg">
                  <p>ID: {u.id}, Username: {u.username}</p>
                  <button onClick={() => setSelectedUser(u)} className="bg-blue-600 p-1 rounded mr-2 hover:bg-blue-700">Ver</button>
                  <button onClick={() => toggleSuspendUser(u.id)} className="bg-yellow-600 p-1 rounded mr-2 hover:bg-yellow-700">
                    {u.suspended ? 'Desuspender' : 'Suspender'}
                  </button>
                  <button onClick={() => toggleBanUser(u.id)} className="bg-red-600 p-1 rounded mr-2 hover:bg-red-700">
                    {u.banned ? 'Desbanir' : 'Banir'}
                  </button>
                </div>
              ))}
              {selectedUser && (
                <div className="mt-4 bg-gray-800 p-4 rounded-lg">
                  <h3 className="text-xl font-semibold">Perfil do Usuário</h3>
                  <p>ID: {selectedUser.id}</p>
                  <p>Username: {selectedUser.username}</p>
                  <p>Depósitos Hoje: ${selectedUser.depositsToday}</p>
                  <p>Total de Depósitos: ${selectedUser.totalDeposits}</p>
                  <p>Usuários Vinculados: {selectedUser.linkedUsers}</p>
                  <p>Depósitos Vinculados: ${selectedUser.linkedDeposits}</p>
                  <button onClick={() => setSelectedUser(null)} className="bg-gray-600 p-2 rounded mt-2 hover:bg-gray-700">Fechar</button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    );
  };

  const Home = () => {
    const activeProducts = products.filter(p => new Date(p.expiry) > new Date());

    return (
      <div className="p-4">
        <h2 className="text-2xl font-bold mb-4">Catálogo</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {activeProducts.map((product) => (
            <div key={product._id} className="bg-gray-800 p-4 rounded-lg">
              <img src={product.image} alt={product.name} className="w-full h-32 object-cover mb-2" />
              <h3 className="text-lg font-semibold">{product.name}</h3>
              <p className="text-blue-400">${product.price} USDT</p>
              <p>Expira: {product.expiry}</p>
              <button className="mt-2 bg-blue-600 p-2 rounded w-full hover:bg-blue-700">Comprar</button>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const renderPage = () => {
    if (currentPage === 'user-login') return <UserLoginRegister />;
    if (currentPage === 'admin-login') return <AdminLogin />;
    if (currentPage === 'moderator-login') return <ModeratorLogin />;
    if (isAdmin) return <AdminDashboard />;
    if (isModerator) return <ModeratorDashboard />;
    if (isAuthenticated) return <Home />;
    return <UserLoginRegister />;
  };

  return (
    <div className="min-h-screen bg-gray-900">
      {renderPage()}
    </div>
  );
};

ReactDOM.render(<App />, document.getElementById('root'));
