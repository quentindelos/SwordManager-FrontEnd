const API_URL = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
    ? "http://localhost:3000" 
    : "https://api.swordmanager.cloud";

// État de session strict en mémoire volatile
let vaultEntries = [];
let userToken = null;  
let vaultKey = null;   
let inactivityTimer = null;

const masterScreen = document.getElementById("master-screen");
const vaultScreen = document.getElementById("vault-screen");
const masterEmailInput = document.getElementById("master-email");
const masterPasswordInput = document.getElementById("master-password");
const unlockBtn = document.getElementById("unlock-btn");
const registerBtn = document.getElementById("register-btn");
const masterError = document.getElementById("master-error");
const lockBtn = document.getElementById("lock-btn");
const toggleFormBtn = document.getElementById("toggle-form-btn");

const searchInput = document.getElementById("search-input");
const entriesBody = document.getElementById("entries-body");

const entryForm = document.getElementById("entry-form");
const entryIdInput = document.getElementById("entry-id");
const entryNameInput = document.getElementById("entry-name");
const entryUrlInput = document.getElementById("entry-url");
const entryUsernameInput = document.getElementById("entry-username");
const entryPasswordInput = document.getElementById("entry-password");
const generateBtn = document.getElementById("generate-btn");
const resetFormBtn = document.getElementById("reset-form-btn");
const genNumbersCheck = document.getElementById("gen-numbers");
const genSpecialsCheck = document.getElementById("gen-specials");
const submitEntryBtn = document.getElementById("submit-entry-btn");
const strengthBar = document.getElementById("password-strength");

// UTILS : ENCODAGE & TOAST
function strToArrayBuffer(str) { return new TextEncoder().encode(str); }
function arrayBufferToStr(buf) { return new TextDecoder().decode(buf); }
function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) { binary += String.fromCharCode(bytes[i]); }
  return btoa(binary);
}
function base64ToBuf(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) { bytes[i] = binary.charCodeAt(i); }
  return bytes.buffer;
}

function showToast(message) {
  const toast = document.getElementById("toast");
  if (!toast) return;
  toast.innerText = message;
  toast.className = "toast-visible";
  setTimeout(() => { toast.className = "toast-hidden"; }, 4000);
}

// Fonction asynchrone isolée pour calculer le SHA-1 local (requis pour RockYou API)
async function sha1(str) {
  const buf = new TextEncoder().encode(str);
  const hashBuf = await crypto.subtle.digest("SHA-1", buf);
  return Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("").toUpperCase();
}

// SÉCURITÉ : AUTO-LOCK (5 min d'inactivité)
function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  if (userToken) {
    inactivityTimer = setTimeout(() => {
      handleLogout();
      showToast("🔒 Session verrouillée automatiquement pour inactivité.");
    }, 5 * 60 * 1000);
  }
}

function initSecurityListeners() {
  window.addEventListener("mousemove", resetInactivityTimer);
  window.addEventListener("keydown", resetInactivityTimer);
}

function destroySecurityListeners() {
  window.removeEventListener("mousemove", resetInactivityTimer);
  window.removeEventListener("keydown", resetInactivityTimer);
  clearTimeout(inactivityTimer);
}

// CRYPTO ENGINE (600 000 Itérations PBKDF2)
async function deriveKeys(password, email) {
  const baseKey = await crypto.subtle.importKey(
    "raw", strToArrayBuffer(password), { name: "PBKDF2" }, false, ["deriveKey"]
  );

  // 1. Clé d'encryption principale locale
  const encryptionKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: strToArrayBuffer(email), iterations: 600000, hash: "SHA-256" },
    baseKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );

  // 2. Hash d'authentification destiné à l'API
  const rawEncryptionKey = await crypto.subtle.exportKey("raw", encryptionKey);
  const authHashBuffer = await crypto.subtle.digest("SHA-256", rawEncryptionKey);
  const authHashHex = Array.from(new Uint8Array(authHashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return { encryptionKey, authHash: authHashHex };
}

async function encryptString(plaintext, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, strToArrayBuffer(plaintext));
  return bufToBase64(iv.buffer) + ":" + bufToBase64(ciphertext);
}

async function decryptString(data, key) {
  const [ivB64, ctB64] = data.split(":");
  if (!ivB64 || !ctB64) throw new Error("Format corrompu");
  const iv = new Uint8Array(base64ToBuf(ivB64));
  const ciphertext = base64ToBuf(ctB64);
  const plaintextBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return arrayBufferToStr(plaintextBuf);
}

// VALIDATIONS CLIENTS 
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ANALYSEUR DE FORCE VISUEL EN TEMPS RÉEL (SANS TOAST AGACANT)
function checkPasswordStrength(password) {
  if (!strengthBar) return;
  strengthBar.className = "strength-bar";

  if (!password) return;

  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 14) score++;
  if (/\d/.test(password)) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (score <= 2) {
    strengthBar.classList.add("weak"); // Rouge
  } else if (score <= 4) {
    strengthBar.classList.add("medium"); // Orange
  } else {
    strengthBar.classList.add("strong"); // Vert
  }
}

// ACTIONS API RESTRUCTURÉES
async function handleRegister() {
  const email = masterEmailInput.value.trim();
  const pwd = masterPasswordInput.value;
  masterError.textContent = "";

  if (!validateEmail(email)) {
    masterError.textContent = "Format d'adresse email invalide.";
    return;
  }
  if (pwd.length < 12) {
    masterError.textContent = "Sécurité insuffisante : le mot de passe doit faire 12 caractères minimum.";
    return;
  }

  registerBtn.disabled = true;
  unlockBtn.disabled = true;
  registerBtn.textContent = "Calcul des clés...";

  try {
    const { encryptionKey, authHash } = await deriveKeys(pwd, email);
    const rawVaultKey = crypto.getRandomValues(new Uint8Array(32));
    const protectedKey = await encryptString(bufToBase64(rawVaultKey.buffer), encryptionKey);

    const res = await fetch(`${API_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password: authHash, protectedKey })
    });
    const data = await res.json();

    if (res.ok) {
      masterError.style.color = "#22c55e";
      masterError.textContent = "Compte créé avec succès ! Connectez-vous.";
      showToast("Compte créé avec succès !");
    } else {
      masterError.style.color = "#f97373";
      masterError.textContent = data.error || "Erreur d'inscription.";
    }
  } catch (e) {
    console.error(e);
    if (e instanceof TypeError && e.message.includes('fetch')) {
      masterError.textContent = "Impossible de joindre le serveur Cloud. Lancez 'node index.js' sur le port 3000 !";
    } else {
      masterError.textContent = "Erreur crypto locale.";
    }
  } finally {
    registerBtn.disabled = false;
    unlockBtn.disabled = false;
    registerBtn.textContent = "S'inscrire";
  }
}

async function handleLogin() {
  const email = masterEmailInput.value.trim();
  const pwd = masterPasswordInput.value;
  masterError.style.color = "#f97373";
  masterError.textContent = "";

  if (!email || !pwd) {
    masterError.textContent = "Identifiants requis.";
    return;
  }

  unlockBtn.disabled = true;
  registerBtn.disabled = true;
  unlockBtn.textContent = "Chiffrement...";

  try {
    const { encryptionKey, authHash } = await deriveKeys(pwd, email);

    const res = await fetch(`${API_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password: authHash }),
    });
    const data = await res.json();

    if (!res.ok || !data.token) {
      masterError.textContent = data.error || "Identifiants erronés.";
      return;
    }

    userToken = data.token;
    const rawKeyB64 = await decryptString(data.protectedKey, encryptionKey);
    
    // PERSISTANCE : Sauvegarde temporaire (Max 15 min)
    const sessionData = {
      token: userToken,
      keyB64: rawKeyB64,
      expiresAt: Date.now() + (15 * 60 * 1000)
    };
    sessionStorage.setItem("sword_session", JSON.stringify(sessionData));

    vaultKey = await crypto.subtle.importKey(
      "raw", base64ToBuf(rawKeyB64), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
    );

    await fetchVaultItems();

    masterPasswordInput.value = "";
    masterScreen.classList.add("hidden");
    vaultScreen.classList.remove("hidden");

    initSecurityListeners();
    resetInactivityTimer();
    renderEntries();
    showToast("🔓 Coffre déverrouillé et synchronisé.");
  } catch (e) {
    console.error(e);
    masterError.textContent = "Identifiants invalides ou échec de déchiffrement.";
  } finally {
    unlockBtn.disabled = false;
    registerBtn.disabled = false;
    unlockBtn.textContent = "Se connecter";
  }
}

async function fetchVaultItems() {
  const res = await fetch(`${API_URL}/vault`, {
    headers: { "Authorization": `Bearer ${userToken}` }
  });
  const encryptedItems = await res.json();

  vaultEntries = [];
  for (let item of encryptedItems) {
    try {
      const decryptedPayload = await decryptString(item.encryptedData, vaultKey);
      const entryData = JSON.parse(decryptedPayload);
      
      vaultEntries.push({
        id: item.id,
        name: item.label,
        url: entryData.url,
        username: entryData.username,
        password: entryData.password
      });
    } catch (err) {
      console.error("Échec déchiffrement d'une ligne.");
    }
  }
}

// UI : AFFICHAGE
function renderEntries(filter = "") {
  entriesBody.innerHTML = "";
  const lowerFilter = filter.trim().toLowerCase();

  vaultEntries
    .filter((entry) => !lowerFilter ? true : (entry.name || "").toLowerCase().includes(lowerFilter))
    .forEach((entry, index) => {
      const tr = document.createElement("tr");

      const tdName = document.createElement("td");
      tdName.setAttribute("data-label", "Nom");
      tdName.textContent = entry.name || "";
      tr.appendChild(tdName);

      const tdUrl = document.createElement("td");
      tdUrl.setAttribute("data-label", "URL");
      if (entry.url) {
        const a = document.createElement("a");
        a.href = entry.url; a.textContent = entry.url; a.target = "_blank"; a.rel = "noopener noreferrer";
        tdUrl.appendChild(a);
      }
      tr.appendChild(tdUrl);

      const tdUsername = document.createElement("td");
      tdUsername.setAttribute("data-label", "Identifiant");
      
      const usernameSpan = document.createElement("span");
      usernameSpan.textContent = entry.username || "";
      tdUsername.appendChild(usernameSpan);

      if (entry.username) {
        const copyUserBtn = document.createElement("button");
        copyUserBtn.className = "toggle-pw-btn";
        copyUserBtn.textContent = "📋";
        copyUserBtn.title = "Copier l'identifiant";
        copyUserBtn.style.marginLeft = "8px";
        
        copyUserBtn.addEventListener("click", () => { 
          navigator.clipboard.writeText(entry.username).then(() => {
            showToast("📋 Identifiant copié !");
          });
        });
        tdUsername.appendChild(copyUserBtn);
      }
      tr.appendChild(tdUsername);

      const tdPassword = document.createElement("td");
      tdPassword.setAttribute("data-label", "Mot de passe");
      const pwSpan = document.createElement("span");
      pwSpan.className = "hidden-password";
      pwSpan.textContent = "••••••••";
      
      const toggleBtn = document.createElement("button");
      toggleBtn.className = "toggle-pw-btn";
      toggleBtn.textContent = "👁️";
      toggleBtn.addEventListener("click", () => {
        if (pwSpan.textContent === "••••••••") {
          pwSpan.textContent = entry.password;
          pwSpan.className = ""; 
        } else {
          pwSpan.textContent = "••••••••";
          pwSpan.className = "hidden-password";
        }
      });
      tdPassword.appendChild(pwSpan);
      tdPassword.appendChild(toggleBtn);
      tr.appendChild(tdPassword);

      const tdActions = document.createElement("td");
      tdActions.setAttribute("data-label", "Actions");
      
      const copyBtn = document.createElement("button");
      copyBtn.textContent = "Copier";
      copyBtn.className = "action-btn edit";
      copyBtn.addEventListener("click", () => { copyToClipboard(entry.password); });

      const editBtn = document.createElement("button");
      editBtn.textContent = "Éditer";
      editBtn.className = "action-btn edit";
      editBtn.style.background = "#2563eb";
      editBtn.addEventListener("click", () => { loadEntryIntoForm(index); });

      const delBtn = document.createElement("button");
      delBtn.textContent = "Supprimer";
      delBtn.className = "action-btn delete";
      delBtn.addEventListener("click", async () => {
        if (confirm("Supprimer définitivement cet identifiant du cloud ?")) {
          if (entry.id) {
            await fetch(`${API_URL}/vault/${entry.id}`, {
              method: "DELETE",
              headers: { "Authorization": `Bearer ${userToken}` }
            });
          }
          vaultEntries.splice(index, 1);
          renderEntries(searchInput.value);
          showToast("Supprimé.");
        }
      });

      tdActions.appendChild(copyBtn);
      tdActions.appendChild(editBtn);
      tdActions.appendChild(delBtn);
      tr.appendChild(tdActions);
      entriesBody.appendChild(tr);
    });
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast("📋 Copié ! Le presse-papiers sera nettoyé dans 30 secondes.");
    
    setTimeout(() => {
      navigator.clipboard.readText().then(currentText => {
        if (currentText === text) {
          navigator.clipboard.writeText("");
          showToast("🧹 Presse-papiers nettoyé par sécurité.");
        }
      }).catch(() => {});
    }, 30000);
  });
}

function handleLogout() {
  sessionStorage.removeItem("sword_session"); 
  userToken = null;
  vaultKey = null;
  vaultEntries = [];

  destroySecurityListeners();

  vaultScreen.classList.add("hidden");
  masterScreen.classList.remove("hidden");
  masterError.style.color = "#9ca3af";
  masterError.textContent = "Session verrouillée.";
}

function resetForm() {
  entryIdInput.value = ""; 
  entryNameInput.value = ""; 
  entryUrlInput.value = ""; 
  entryUsernameInput.value = ""; 
  entryPasswordInput.value = "";
  submitEntryBtn.textContent = "Enregistrer"; 
  
  if (strengthBar) strengthBar.className = 'strength-bar';

  entryForm.classList.add("hidden");
  toggleFormBtn.textContent = "➕ Ajouter un identifiant";
  toggleFormBtn.style.background = "#2563eb"; 
}

function loadEntryIntoForm(index) {
  const entry = vaultEntries[index];
  entryIdInput.value = entry.id || ""; 
  
  entryNameInput.value = entry.name || "";
  entryUrlInput.value = entry.url || "";
  entryUsernameInput.value = entry.username || "";
  entryPasswordInput.value = entry.password || "";
  
  submitEntryBtn.textContent = "Mettre à jour"; 
  checkPasswordStrength(entry.password || "");

  entryForm.classList.remove("hidden");
  toggleFormBtn.textContent = "❌ Fermer le formulaire";
  toggleFormBtn.style.background = "#6b7280"; 

  window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
}

// ÉVÉNEMENTS GENERAUX
unlockBtn.addEventListener("click", handleLogin);
registerBtn.addEventListener("click", handleRegister);
lockBtn.addEventListener("click", handleLogout);
searchInput.addEventListener("input", () => { renderEntries(searchInput.value); });
resetFormBtn.addEventListener("click", resetForm);

entryPasswordInput.addEventListener("input", (e) => {
  checkPasswordStrength(e.target.value);
});

// ÉVÉNEMENT DU SUBMIT (AVEC FILTRE DE VÉRIFICATION ROCKYOU)
entryForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  const inputPassword = entryPasswordInput.value;

  if (inputPassword) {
    try {
      const hash = await sha1(inputPassword);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      if (res.ok) {
        const text = await res.text();
        const isPwned = text.split("\n").some(line => line.startsWith(suffix));

        if (isPwned) {
          if (strengthBar) strengthBar.className = "strength-bar weak"; 
          
          const localTrollMessages = [
            "Tu ne vas pas mettre ce mot de passe quand même... ? 😒",
            "Allez, encore un effort... ! 💪",
            "Même mon chat tape un meilleur mot de passe que ça. 🐱",
            "Un hacker rigole déjà en voyant ça. 🏴‍☠️",
            "Ce mot de passe est plus connu que la recette des crêpes. 🥞",
            "Zéro effort décelé. Réessaie encore. 🛑",
            "Ce mot de passe est dans RockYou. Autant ne rien mettre à ce stade... 💀",
            "Franchement, j'ai vu des passoires plus étanches que ce mot de passe. 🚰",
            "Même en 1995, ce mot de passe était déjà considéré comme périmé. 📅",
            "Félicitations, tu viens de choisir le mot de passe préféré des bots russes. 🤖",
            "Un peu d'originalité s'il te plaît, ma base de données s'endort... 💤",
            "Si la paresse avait un mot de passe, ce serait exactement celui-là. 🦥",
            "Tu as trouvé ça dans un biscuit de la fortune ou c'est naturel ? 🥠",
            "Le chiffrement AES-GCM 256 bits mérite mieux que d'abriter ça... ⚖️",
            "Je refuse de synchroniser un truc pareil sur GCP, question d'honneur. ☁️",
            "Erreur 404 : Imagination introuvable. Essaie encore ! 🔍",
            "Même pas besoin d'IA pour deviner ça, un enfant de 4 ans y arrive. 👶",
            "À ce niveau-là, laisse la porte ouverte et donne directement les clés. 🔑",
            "Même l'authentification de mon vieux routeur de 2004 refuserait un truc pareil. 🔌",
            "Un script d'une ligne en Python trouverait ça en moins de deux millisecondes. 🐍",
            "C'est un mot de passe ou un code de carte fidélité ? Sois sérieux deux minutes. 🛒",
            "Tu as confondu l'option 'Créer un mot de passe' avec 'Donner mes données au premier venu'. 🎁",
            "Si j'étais un rançongiciel, je t'enverrais un message de remerciement. 🏴‍☠️",
            "Je crois que la jauge de force vient de faire une dépression nerveuse. 📉",
            "Mettre ça, c'est comme laisser la clé sur la serrure avec un panneau 'Entrez c'est ouvert'. 🚪",
            "Ton niveau d'imagination est actuellement plus bas que la sécurité d'un objet connecté chinois. 📡",
            "Même une attaque par dictionnaire hors-ligne plierait l'affaire avant que j'aie le temps de cligner des yeux. ⚡"
          ];
          
          const randomPhrase = localTrollMessages[Math.floor(Math.random() * localTrollMessages.length)];
          
          const toast = document.getElementById("toast");
          if (toast) {
            toast.innerText = `🛑 Refusé ! ${randomPhrase}`;
            toast.className = "toast-visible";
            setTimeout(() => { toast.className = "toast-hidden"; }, 10000);
          }
          
          return; // 🛑 BLOQUÉ
        }
      }
    } catch (err) {
      console.error("Erreur lors de la vérification API RockYou :", err);
    }
  }

  // LOGIQUE DE CHIFFREMENT ET D'ENVOI SI OK
  submitEntryBtn.disabled = true;
  const entryId = entryIdInput.value;

  let rawUrl = entryUrlInput.value.trim();
  if (rawUrl && !/^https?:\/\//i.test(rawUrl)) {
    rawUrl = "https://" + rawUrl;
  }

  const entryDataClear = {
    url: rawUrl, 
    username: entryUsernameInput.value.trim(),
    password: entryPasswordInput.value,
  };

  const label = entryNameInput.value.trim();
  if (!label) {
    submitEntryBtn.disabled = false;
    return alert("Nom requis.");
  }

  try {
    const encryptedData = await encryptString(JSON.stringify(entryDataClear), vaultKey);

    let res;
    if (entryId) {
      res = await fetch(`${API_URL}/vault/${entryId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({ type: "login", label, encryptedData, folder: null }),
      });
    } else {
      res = await fetch(`${API_URL}/vault`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({ type: "login", label, encryptedData, folder: null }),
      });
    }

    if (res.ok) {
      await fetchVaultItems();
      resetForm();
      renderEntries(searchInput.value);
      showToast(entryId ? "🔄 Identifiant mis à jour !" : "💾 Synchronisé avec le Cloud.");
    } else {
      alert("Échec de synchronisation.");
    }
  } catch (err) {
    alert("Erreur technique.");
  } finally {
    submitEntryBtn.disabled = false;
  }
});

// ÉCOUTEUR DU BOUTON GÉNÉRER (CRYPTOGRAPHIQUEMENT SECURE ET CONDITIONNEL)
generateBtn.addEventListener("click", () => {
  entryPasswordInput.value = (() => {
    let allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    if (genNumbersCheck && genNumbersCheck.checked) {
      allowedChars += "0123456789";
    }
    if (genSpecialsCheck && genSpecialsCheck.checked) {
      allowedChars += "()_-,?:§!@#$%^&*=+";
    }
    
    let pw = "";
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    
    for (let i = 0; i < 16; i++) {
      pw += allowedChars[array[i] % allowedChars.length];
    }
    return pw;
  })();
  
  setTimeout(() => {
    checkPasswordStrength(entryPasswordInput.value);
  }, 10);

  showToast("🎲 Mot de passe personnalisé généré.");
});

// LOGIQUE D'AFFICHAGE DU FORMULAIRE (TOGGLE)
toggleFormBtn.addEventListener("click", () => {
  if (entryForm.classList.contains("hidden")) {
    entryForm.classList.remove("hidden");
    toggleFormBtn.textContent = "❌ Fermer le formulaire";
    toggleFormBtn.style.background = "#6b7280"; 
    entryForm.scrollIntoView({ behavior: "smooth" });
  } else {
    resetForm();
  }
});

// RESTAURATION AUTOMATIQUE DE SESSION (F5)
window.addEventListener("DOMContentLoaded", async () => {
  const cachedSession = sessionStorage.getItem("sword_session");
  if (!cachedSession) return; 

  try {
    const sessionData = JSON.parse(cachedSession);

    if (Date.now() > sessionData.expiresAt) {
      sessionStorage.removeItem("sword_session");
      return;
    }

    userToken = sessionData.token;
    vaultKey = await crypto.subtle.importKey(
      "raw", base64ToBuf(sessionData.keyB64), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
    );

    await fetchVaultItems();
    
    masterScreen.classList.add("hidden");
    vaultScreen.classList.remove("hidden");
    
    initSecurityListeners();
    resetInactivityTimer();
    renderEntries();
    showToast("🔄 Session restaurée automatiquement.");
  } catch (err) {
    console.error("Échec de la restauration de session :", err);
    sessionStorage.removeItem("sword_session");
  }
});
