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
const submitEntryBtn = document.getElementById("submit-entry-btn");

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
  toast.innerText = message;
  toast.className = "toast-visible";
  setTimeout(() => { toast.className = "toast-hidden"; }, 4000);
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

//VALIDATIONS CLIENTS 
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
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

    const res = await fetch(`${API_URL}/api/auth/register`, {
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
    // Si l'erreur est provoquée par fetch(), c'est que le serveur Node (port 3000) est déconnecté
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

    const res = await fetch(`${API_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password: authHash })
    });
    const data = await res.json();

    if (!res.ok || !data.token) {
      masterError.textContent = data.error || "Identifiants erronés.";
      return;
    }

    userToken = data.token;
    const rawKeyB64 = await decryptString(data.protectedKey, encryptionKey);
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
    masterError.textContent = "Identifiants invalides ou échec de déchiffrement.";
  } finally {
    unlockBtn.disabled = false;
    registerBtn.disabled = false;
    unlockBtn.textContent = "Se connecter";
  }
}

async function fetchVaultItems() {
  const res = await fetch(`${API_URL}/api/vault`, {
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

// UI : AFFICHAGE AVEC CELLULES SÉCURISÉES
function renderEntries(filter = "") {
  entriesBody.innerHTML = "";
  const lowerFilter = filter.trim().toLowerCase();

  vaultEntries
    .filter((entry) => !lowerFilter ? true : (entry.name || "").toLowerCase().includes(lowerFilter))
    .forEach((entry, index) => {
      const tr = document.createElement("tr");

      const tdName = document.createElement("td");
      tdName.textContent = entry.name || "";
      tr.appendChild(tdName);

      const tdUrl = document.createElement("td");
      if (entry.url) {
        const a = document.createElement("a");
        a.href = entry.url; a.textContent = entry.url; a.target = "_blank"; a.rel = "noopener noreferrer";
        tdUrl.appendChild(a);
      }
      tr.appendChild(tdUrl);

      const tdUsername = document.createElement("td");
      tdUsername.textContent = entry.username || "";
      tr.appendChild(tdUsername);

      // Système d'affichage par bouton œil
      const tdPassword = document.createElement("td");
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

      // Actions : Édition / Copie / Suppression
      const tdActions = document.createElement("td");
      
      const copyBtn = document.createElement("button");
      copyBtn.textContent = "Copier";
      copyBtn.className = "action-btn edit"; // Réutilise ton style vert
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
            await fetch(`${API_URL}/api/vault/${entry.id}`, {
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
    
    // Nettoyage automatique du presse-papiers
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
  userToken = null; vaultKey = null; vaultEntries = [];
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
  submitEntryBtn.textContent = "Enregistrer"; // Remet le texte d'origine
}

function loadEntryIntoForm(index) {
  const entry = vaultEntries[index];
  // Correction ici : on stocke le vrai ID SQL (UUID) de l'élément
  entryIdInput.value = entry.id || ""; 
  
  entryNameInput.value = entry.name || "";
  entryUrlInput.value = entry.url || "";
  entryUsernameInput.value = entry.username || "";
  entryPasswordInput.value = entry.password || "";
  
  // Petit bonus visuel pour savoir que tu es en mode édition
  submitEntryBtn.textContent = "Mettre à jour"; 
  window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
}

// ÉVÈNEMENT
unlockBtn.addEventListener("click", handleLogin);
registerBtn.addEventListener("click", handleRegister);
lockBtn.addEventListener("click", handleLogout);
searchInput.addEventListener("input", () => { renderEntries(searchInput.value); });

entryForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  submitEntryBtn.disabled = true;

  const entryId = entryIdInput.value; // Récupère l'ID injecté par loadEntryIntoForm

  const entryDataClear = {
    url: entryUrlInput.value.trim(),
    username: entryUsernameInput.value.trim(),
    password: entryPasswordInput.value
  };

  const label = entryNameInput.value.trim();
  if (!label) return alert("Nom requis.");

  try {
    const encryptedData = await encryptString(JSON.stringify(entryDataClear), vaultKey);

let res;
    if (entryId) {
      res = await fetch(`${API_URL}/api/vault/${entryId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${userToken}` },
        body: JSON.stringify({ type: "login", label, encryptedData, folder: null })
      });
    } else {
      res = await fetch(`${API_URL}/api/vault`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${userToken}` },
        body: JSON.stringify({ type: "login", label, encryptedData, folder: null })
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

generateBtn.addEventListener("click", () => { 
  entryPasswordInput.value = (() => {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
    let pw = ""; const array = new Uint32Array(16); crypto.getRandomValues(array);
    for (let i = 0; i < 16; i++) { pw += chars[array[i] % chars.length]; }
    return pw;
  })();
  showToast("🎲 Mot de passe fort généré.");
});

resetFormBtn.addEventListener("click", resetForm);
