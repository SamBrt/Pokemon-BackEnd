require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Configura la connessione al database MySQL (usando le impostazioni di MAMP)
const db = mysql.createConnection({
  host: "localhost",
  user: "root", // Questo è l'utente di default di MAMP
  password: "root", // Password di default di MAMP
  database: "pokemon_db",
  port: 8889, // Porta di default per MySQL su MAMP
});

// Connetti al database
db.connect((err) => {
  if (err) {
    console.error("Errore di connessione al database:", err);
  } else {
    console.log("Connesso al database MySQL");
    console.log("Server in ascolto sulla porta", PORT);
  }
});

// Funzione per registrare eventi di log nel database
const logEvent = (userId, event, description) => {
  const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
  db.query(
    "INSERT INTO logs (user_id, event, description, timestamp) VALUES (?, ?, ?, ?)",
    [userId, event, description, timestamp],
    (err) => {
      if (err) {
        console.error("Errore durante il logging dell'evento:", err);
      }
    }
  );
};

// Rotta per la registrazione degli utenti
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  // Controllo se l'utente esiste già
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) {
      console.error("Errore durante la verifica dell'utente:", err);
      logEvent(null, "Errore Registrazione", `Errore durante la verifica dell'utente: ${err.message}`);
      return res.status(500).json({ message: "Errore del server" });
    }
    if (results.length > 0) {
      logEvent(null, "Tentativo di Registrazione Fallito", `Email già registrata: ${email}`);
      return res.status(400).json({ message: "Email già registrata" });
    }

    // Hash della password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Ottieni la data di registrazione corrente
    const registrationDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

    // Inserisci il nuovo utente nel database
    db.query(
      "INSERT INTO users (username, email, password, registrationDate) VALUES (?, ?, ?, ?)",
      [username, email, hashedPassword, registrationDate],
      (err, result) => {
        if (err) {
          console.error("Errore durante la registrazione:", err);
          logEvent(null, "Errore Registrazione", `Errore durante la registrazione: ${err.message}`);
          return res.status(500).json({ message: "Errore del server" });
        }
        const userId = result.insertId;
        logEvent(userId, "Registrazione", `L'utente ${username} si è registrato con successo.`);
        res.status(201).json({ message: "Registrazione completata" });
      }
    );
  });
});

// Rotta per il login degli utenti
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) {
      console.error("Errore durante il login:", err);
      logEvent(null, "Errore Login", `Errore durante il login: ${err.message}`);
      return res.status(500).json({ message: "Errore del server" });
    }

    if (results.length === 0) {
      logEvent(null, "Tentativo di Login Fallito", `Email non trovata: ${email}`);
      return res.status(400).json({ message: "Email non trovata" });
    }

    const user = results[0];

    // Verifica la password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logEvent(user.id, "Tentativo di Login Fallito", "Password errata.");
      return res.status(400).json({ message: "Password errata" });
    }

    logEvent(user.id, "Login", `L'utente ${user.username} ha effettuato l'accesso con successo.`);
    res.status(200).json({
      message: "Login riuscito",
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        registrationDate: user.registrationDate,
      },
    });
  });
});

// Rotta PUT: Aggiorna il profilo utente
app.put("/updateProfile/:id", async (req, res) => {
  const { id } = req.params;
  const { username, oldPassword, newPassword } = req.body;

  // Cerca l'utente per ID
  db.query("SELECT * FROM users WHERE id = ?", [id], async (err, results) => {
    if (err) {
      console.error("Errore durante la verifica dell'utente:", err);
      logEvent(id, "Errore Aggiornamento Profilo", `Errore durante la verifica dell'utente: ${err.message}`);
      return res.status(500).json({ message: "Errore del server" });
    }

    if (results.length === 0) {
      logEvent(id, "Aggiornamento Profilo Fallito", "Utente non trovato.");
      return res.status(404).json({ message: "Utente non trovato" });
    }

    const user = results[0];

    // Verifica la vecchia password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      logEvent(id, "Aggiornamento Profilo Fallito", "Vecchia password errata.");
      return res.status(400).json({ message: "Vecchia password errata" });
    }

    // Hash della nuova password (se presente)
    let updatedPassword = user.password;
    if (newPassword) {
      const salt = await bcrypt.genSalt(10);
      updatedPassword = await bcrypt.hash(newPassword, salt);
    }

    // Aggiorna i dati dell'utente
    db.query(
      "UPDATE users SET username = ?, password = ? WHERE id = ?",
      [username, updatedPassword, id],
      (err, result) => {
        if (err) {
          console.error("Errore durante l'aggiornamento del profilo:", err);
          logEvent(id, "Errore Aggiornamento Profilo", `Errore durante l'aggiornamento del profilo: ${err.message}`);
          return res.status(500).json({ message: "Errore durante l'aggiornamento del profilo" });
        }
        logEvent(id, "Aggiornamento Profilo", `Il profilo dell'utente ${username} è stato aggiornato.`);
        res.status(200).json({ message: "Profilo aggiornato con successo" });
      }
    );
  });
});

// Rotta DELETE: Elimina l'account dell'utente
app.delete("/deleteAccount/:id", (req, res) => {
  const userId = req.params.id;

  db.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
    if (err) {
      console.error("Errore durante la verifica dell'utente:", err);
      logEvent(userId, "Errore Eliminazione Account", `Errore durante la verifica dell'utente: ${err.message}`);
      return res.status(500).json({ message: "Errore del server" });
    }

    if (results.length === 0) {
      logEvent(userId, "Eliminazione Account Fallita", "ID utente non trovato.");
      return res.status(404).json({ message: "ID utente non trovato" });
    }

    db.query("DELETE FROM users WHERE id = ?", [userId], (err) => {
      if (err) {
        console.error("Errore durante l'eliminazione dell'account:", err);
        logEvent(userId, "Errore Eliminazione Account", `Errore durante l'eliminazione dell'account: ${err.message}`);
        return res.status(500).json({ message: "Errore del server" });
      }
      logEvent(userId, "Eliminazione Account", `L'account dell'utente con ID ${userId} è stato eliminato.`);
      res.status(200).json({ message: "Account eliminato con successo" });
    });
  });
});

// Avvio del server
app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});
