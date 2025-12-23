import { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import './App.css'; 

function App() {
  // --- CONFIGURATION DE L'ADRESSE DU SERVEUR ---
  // On utilise l'adresse de votre serveur Render
  const API_URL = "https://intellivano-project.onrender.com"; 

  const [token, setToken] = useState(localStorage.getItem('token'));
  const [isLogin, setIsLogin] = useState(true);
  
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [username, setUsername] = useState('');
  
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  
  // États pour l'image
  const [selectedImage, setSelectedImage] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);
  
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };
  useEffect(scrollToBottom, [messages]);

  // Auth
  const handleAuth = async (e) => {
    e.preventDefault();
    const endpoint = isLogin ? '/login' : '/register';
    const payload = isLogin ? { email, password } : { email, password, username };

    try {
      // UTILISATION DE LA NOUVELLE URL ICI
      const res = await axios.post(`${API_URL}${endpoint}`, payload);
      
      if (isLogin) {
        setToken(res.data.token);
        localStorage.setItem('token', res.data.token);
      } else {
        alert("Compte créé ! Connectez-vous.");
        setIsLogin(true);
      }
    } catch (err) {
      console.error(err);
      alert("Erreur : " + (err.response?.data?.msg || "Impossible de joindre le serveur. Vérifiez que le Backend Render est actif."));
    }
  };

  const logout = () => {
    setToken(null);
    localStorage.removeItem('token');
    setMessages([]);
  };

  // Gestion Image
  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setSelectedImage(reader.result);
        setPreviewUrl(URL.createObjectURL(file));
      };
      reader.readAsDataURL(file);
    }
  };

  const sendMessage = async () => {
    if (!input.trim() && !selectedImage) return;
    
    // Affichage local
    const userMsgContent = selectedImage 
      ? (<div><img src={previewUrl} alt="upload" style={{maxWidth:'100px', borderRadius:'10px', marginBottom:'5px'}}/><br/>{input}</div>) 
      : input;

    const userMsg = { role: 'user', content: userMsgContent };
    setMessages(prev => [...prev, userMsg]);
    
    setLoading(true);
    const textToSend = input;
    const imageToSend = selectedImage;
    
    setInput('');
    setSelectedImage(null);
    setPreviewUrl(null);

    try {
      // UTILISATION DE LA NOUVELLE URL ICI AUSSI
      const res = await axios.post(`${API_URL}/chat`, 
        { message: textToSend, image: imageToSend }, 
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setMessages(prev => [...prev, { role: 'ai', content: res.data.response }]);
    } catch (err) {
      console.error(err);
      setMessages(prev => [...prev, { role: 'ai', content: "⚠️ Erreur serveur (Vérifiez Render)." }]);
    }
    setLoading(false);
  };

  if (!token) {
    return (
      <div className="app-wrapper">
        <div className="login-card">
          <h2 className="brand-title">Intellivano</h2>
          <p className="subtitle">{isLogin ? "Bon retour" : "Créer un compte"}</p>
          <form onSubmit={handleAuth}>
            {!isLogin && <input className="custom-input" type="text" placeholder="Nom d'utilisateur" onChange={e => setUsername(e.target.value)} required />}
            <input className="custom-input" type="email" placeholder="Email" onChange={e => setEmail(e.target.value)} required />
            <input className="custom-input" type="password" placeholder="Mot de passe" onChange={e => setPassword(e.target.value)} required />
            <button className="btn-main" type="submit">{isLogin ? "Se connecter" : "S'inscrire"}</button>
          </form>
          <p className="toggle-link" onClick={() => setIsLogin(!isLogin)}>{isLogin ? "Créer un compte" : "Se connecter"}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="app-wrapper">
      <div className="chat-interface">
        <div className="chat-header">
          <div className="logo-area"><span className="emoji">👁️</span><h2>Intellivano Vision</h2></div>
          <button onClick={logout} className="btn-logout">Déconnexion</button>
        </div>

        <div className="chat-container">
          {messages.length === 0 && <div className="empty-state"><h3>Bonjour ! 👋</h3><p>Envoyez une image pour que je l'analyse.</p></div>}
          {messages.map((msg, index) => (
            <div key={index} className={`message ${msg.role === 'user' ? 'user-message' : 'ai-message'}`}>{msg.content}</div>
          ))}
          {loading && <div className="message ai-message loading-msg"><em>Intellivano réfléchit...</em></div>}
          <div ref={messagesEndRef} />
        </div>

        {previewUrl && (
          <div style={{padding:'10px 20px', background:'white', borderTop:'1px solid #eee'}}>
            <span style={{fontSize:'12px', color:'#666'}}>Image jointe : </span>
            <img src={previewUrl} alt="preview" style={{height:'50px', borderRadius:'5px', verticalAlign:'middle'}} />
            <button onClick={()=>{setSelectedImage(null); setPreviewUrl(null)}} style={{marginLeft:'10px', border:'none', background:'transparent', cursor:'pointer', color:'red'}}>❌</button>
          </div>
        )}

        <div className="input-area">
          <input type="file" ref={fileInputRef} onChange={handleFileChange} accept="image/*" style={{display:'none'}} />
          <button onClick={() => fileInputRef.current.click()} style={{background:'#e9ecef', color:'#333', padding:'0 15px', fontSize:'1.2rem'}} title="Joindre une image">📎</button>
          <input type="text" placeholder="Écrivez un message..." value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && sendMessage()} />
          <button onClick={sendMessage}>Envoyer</button>
        </div>
      </div>
    </div>
  );
}

export default App;