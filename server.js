const express = require("express");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3306;

app.use(express.json());
app.use(cors());

// Finto database (array di utenti)
let users = [];

// Funzione per generare ID univoco
const generateUserId = () => {
  return users.length ? users[users.length - 1].id + 1 : 1;
};

// Rotta POST: Registrazione di un nuovo utente
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  console.log("Richiesta di registrazione ricevuta con i seguenti dati:");
  console.log(`Username: ${username}, Email: ${email}, Password: [Nascosta per sicurezza]`);

  // Controlla se esiste già un utente con lo stesso username o email
  const existingUser = users.find(
    (user) => user.username === username || user.email === email
  );
  if (existingUser) {
    console.log("Registrazione fallita: Utente o email già esistenti");
    return res.status(400).json({ message: "Utente o email già esistenti" });
  }

  // Hash della password
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Crea un nuovo utente
    const newUser = {
      id: generateUserId(),
      username,
      email,
      password: hashedPassword,
    };

    // Aggiungi il nuovo utente al "database"
    users.push(newUser);

    console.log("Nuovo utente registrato con successo:");
    console.log(`ID: ${newUser.id}, Username: ${newUser.username}, Email: ${newUser.email}`);

    res.status(201).json({ message: "Registrazione completata" });
  } catch (error) {
    console.log("Errore durante la registrazione:", error);
    res.status(500).json({ message: "Errore nella registrazione" });
  }
});

// Rotta POST: Login utente
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  console.log("Richiesta di login ricevuta per l'email:", email);

  // Cerca l'utente in base all'email
  const user = users.find((user) => user.email === email);
  if (!user) {
    console.log("Login fallito: Email non trovata");
    return res.status(400).json({ message: "Email non trovata" });
  }

  // Confronta la password inserita con quella hashata
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    console.log("Login fallito: Password errata");
    return res.status(400).json({ message: "Password errata" });
  }

  console.log("Login riuscito per l'utente:");
  console.log(`ID: ${user.id}, Username: ${user.username}, Email: ${user.email}`);

  // Se tutto è corretto, ritorna le informazioni dell'utente
  res.status(200).json({
    message: "Login riuscito",
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
    },
  });
});

// Rotta GET: Ottieni informazioni su tutti gli utenti
app.get("/users", (req, res) => {
  const userList = users.map((user) => ({
    id: user.id,
    username: user.username,
    email: user.email,
  }));
  res.json(userList); // Ritorna la lista degli utenti senza la password
});

// Avvia il server
app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});
