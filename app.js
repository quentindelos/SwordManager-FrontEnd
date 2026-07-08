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
const genNumbersCheck = document.getElementById("gen-numbers");
const genSpecialsCheck = document.getElementById("gen-specials");
const resetFormBtn = document.getElementById("reset-form-btn");
const submitEntryBtn = document.getElementById("submit-entry-btn");
const exportBtn = document.getElementById("export-btn");
const entryFolderInput = document.getElementById("entry-folder");
const folderFilter = document.getElementById("folder-filter");
const folderList = document.getElementById("folder-list");
const entryFormTitle = document.getElementById("entry-form-title");
const modalCloseBtn = document.querySelector(".modal-close");
const toggleMasterPwBtn = document.getElementById("toggle-master-pw");
const entriesCountEl = document.getElementById("entries-count");

// UTILS : ENCODAGE & TOAST
function strToArrayBuffer(str) {
  return new TextEncoder().encode(str);
}
function arrayBufferToStr(buf) {
  return new TextDecoder().decode(buf);
}
function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
function base64ToBuf(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function showToast(message) {
  const toast = document.getElementById("toast");
  toast.innerText = message;
  toast.className = "toast-visible";
  setTimeout(() => {
    toast.className = "toast-hidden";
  }, 4000);
}

// SÉCURITÉ : AUTO-LOCK (5 min d'inactivité)
function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  if (userToken) {
    inactivityTimer = setTimeout(
      () => {
        handleLogout();
        showToast("🔒 Session verrouillée automatiquement pour inactivité.");
      },
      5 * 60 * 1000,
    );
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
    "raw",
    strToArrayBuffer(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  // 1. Clé d'encryption principale locale
  const encryptionKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: strToArrayBuffer(email),
      iterations: 600000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );

  // 2. Hash d'authentification destiné à l'API
  const rawEncryptionKey = await crypto.subtle.exportKey("raw", encryptionKey);
  const authHashBuffer = await crypto.subtle.digest(
    "SHA-256",
    rawEncryptionKey,
  );
  const authHashHex = Array.from(new Uint8Array(authHashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return { encryptionKey, authHash: authHashHex };
}

async function encryptString(plaintext, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    strToArrayBuffer(plaintext),
  );
  return bufToBase64(iv.buffer) + ":" + bufToBase64(ciphertext);
}

async function decryptString(data, key) {
  const [ivB64, ctB64] = data.split(":");
  if (!ivB64 || !ctB64) throw new Error("Format corrompu");
  const iv = new Uint8Array(base64ToBuf(ivB64));
  const ciphertext = base64ToBuf(ctB64);
  const plaintextBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext,
  );
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
    masterError.textContent =
      "Sécurité insuffisante : le mot de passe doit faire 12 caractères minimum.";
    return;
  }

  registerBtn.disabled = true;
  unlockBtn.disabled = true;
  registerBtn.textContent = "Calcul des clés...";

  try {
    const { encryptionKey, authHash } = await deriveKeys(pwd, email);
    const rawVaultKey = crypto.getRandomValues(new Uint8Array(32));
    const protectedKey = await encryptString(
      bufToBase64(rawVaultKey.buffer),
      encryptionKey,
    );

    const res = await fetch(`${API_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password: authHash, protectedKey }),
    });
    const data = await res.json();

    if (res.ok) {
      masterError.style.color = "#22c55e";
      masterError.textContent = "Compte créé avec succès ! Connectez-vous.";
      showToast("Compte créé avec succès !");
    } else {
      masterError.style.color = "#f97373";

      // 📑 Gestion spécifique de l'adresse email déjà utilisée
      if (res.status === 409 || data.error === "ConflictError") {
        masterError.textContent = "Cette adresse email est déjà utilisée.";
      } else {
        // Message générique pour les autres erreurs
        masterError.textContent = data.error || "Erreur d'inscription.";
      }
    }
  } catch (e) {
    console.error(e);
    // Si l'erreur est provoquée par fetch(), c'est que le serveur Node (port 3000) est déconnecté
    if (e instanceof TypeError && e.message.includes("fetch")) {
      masterError.textContent =
        "Impossible de joindre le serveur Cloud. Lancez 'node index.js' sur le port 3000 !";
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

    // 1. Appel réseau vers l'API d'authentification d'abord
    const res = await fetch(`${API_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password: authHash }),
    });
    const data = await res.json();

    // 2. Vérification du statut de la réponse
    if (!res.ok || !data.token) {
      masterError.textContent = data.error || "Identifiants erronés.";
      return;
    }

    // 3. Extraction des données une fois la connexion validée
    userToken = data.token;
    const rawKeyB64 = await decryptString(data.protectedKey, encryptionKey);

    // 🛠️ SÉCURITÉ & PERSISTANCE : Sauvegarde temporaire pour le rafraîchissement (Max 1h)
    const sessionData = {
      token: userToken,
      keyB64: rawKeyB64,
      expiresAt: Date.now() + 15 * 60 * 1000, // Heure actuelle + 1 heure
    };
    sessionStorage.setItem("sword_session", JSON.stringify(sessionData));

    // 4. Importation de la clé en mémoire volatile
    vaultKey = await crypto.subtle.importKey(
      "raw",
      base64ToBuf(rawKeyB64),
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );

    // 5. Récupération des secrets du coffre
    await fetchVaultItems();

    // Nettoyage de l'interface et bascule d'écran
    masterPasswordInput.value = "";
    masterScreen.classList.add("hidden");
    vaultScreen.classList.remove("hidden");

    initSecurityListeners();
    resetInactivityTimer();
    renderEntries();
    showToast("🔓 Coffre déverrouillé et synchronisé.");
  } catch (e) {
    console.error(e);
    masterError.textContent =
      "Identifiants invalides ou échec de déchiffrement.";
  } finally {
    unlockBtn.disabled = false;
    registerBtn.disabled = false;
    unlockBtn.textContent = "Se connecter";
  }
}

async function fetchVaultItems() {
  try {
    const res = await fetch(`${API_URL}/vault`, {
      headers: { Authorization: `Bearer ${userToken}` },
    });

    if (!res.ok) throw new Error("Impossible de récupérer le coffre-fort");

    const encryptedItems = await res.json();
    vaultEntries = []; // On réinitialise le tableau local

    for (let item of encryptedItems) {
      try {
        // 1. Déchiffrement du payload principal (url, username, password)
        const decryptedPayload = await decryptString(
          item.encryptedData,
          vaultKey,
        );
        const entryData = JSON.parse(decryptedPayload);

        // 2. Gestion sécurisée du dossier (on gère le cas où il est chiffré ou brut)
        let folderValue = null;
        if (item.folder) {
          try {
            // Si ton backend chiffre aussi le dossier, on le déchiffre ici :
            folderValue = await decryptString(item.folder, vaultKey);
          } catch (folderErr) {
            // Si le déchiffrement du dossier échoue, c'est peut-être du texte brut (ancien format)
            folderValue = item.folder;
          }
        }

        // 3. On pousse l'élément sain dans notre tableau
        vaultEntries.push({
          id: item.id,
          name: item.label, // Ton titre/nom
          url: entryData.url || "",
          username: entryData.username || "",
          password: entryData.password || "",
          folder: folderValue ? folderValue.trim() : null,
          // On anticipe les dates pour la suite :
          createdAt: item.createdAt || null,
          updatedAt: item.updatedAt || null,
          expiresAt: entryData.expiresAt || null, // Souvent stocké dans le payload chiffré
        });
      } catch (itemError) {
        // Si UN item a un problème, on l'affiche dans la console mais on NE bloque PAS la boucle !
        console.warn(
          `[Erreur Déchiffrement] Impossible de lire l'item ID ${item.id}:`,
          itemError.message,
        );
      }
    }
  } catch (globalError) {
    console.error(
      "Erreur globale lors de la récupération du coffre :",
      globalError,
    );
    showToast("❌ Erreur de synchronisation du coffre-fort.");
  }
}

// UI : AFFICHAGE AVEC CELLULES SÉCURISÉES (OPTION A - CORRIGÉE)
function renderEntries(filter = "") {
  entriesBody.innerHTML = "";
  const lowerFilter = filter.trim().toLowerCase();
  const selectedFolder = folderFilter ? folderFilter.value : "";

  // 1. MÀJ dynamique des options du menu déroulant (sans écraser la sélection actuelle)
  if (folderFilter) {
    const uniqueFolders = [
      ...new Set(vaultEntries.map((e) => e.folder).filter(Boolean)),
    ];

    // On garde les deux options de base
    let optionsHtml = `<option value="">📁 Tous les dossiers</option>
                       <option value="sans-dossier" ${selectedFolder === "sans-dossier" ? "selected" : ""}>📄 Sans dossier</option>`;

    // On ajoute les dossiers dynamiques
    uniqueFolders.forEach((folder) => {
      optionsHtml += `<option value="${folder}" ${selectedFolder === folder ? "selected" : ""}>📁 ${folder}</option>`;
    });

    folderFilter.innerHTML = optionsHtml;

    // 🛠️ AJOUT : Alimentation dynamique des suggestions (datalist) pour le formulaire
    if (folderList) {
      let datalistHtml = "";
      uniqueFolders.forEach((folder) => {
        datalistHtml += `<option value="${folder}"></option>`;
      });
      folderList.innerHTML = datalistHtml;
    }
  }

  // 2. Filtrage croisé (Texte + Dossier)
  const filteredEntries = vaultEntries.filter((entry) => {
    // Filtre texte (Nom)
    const matchesText = !lowerFilter
      ? true
      : (entry.name || "").toLowerCase().includes(lowerFilter);

    // Filtre dossier
    let matchesFolder = true;
    if (selectedFolder === "sans-dossier") {
      matchesFolder = !entry.folder;
    } else if (selectedFolder !== "") {
      matchesFolder = entry.folder === selectedFolder;
    }

    return matchesText && matchesFolder;
  });

  // 3. Compteur d'identifiants (pour l'orientation de l'utilisateur)
  if (entriesCountEl) {
    const total = vaultEntries.length;
    entriesCountEl.textContent =
      total === 0
        ? "Aucun identifiant enregistré"
        : `${filteredEntries.length} / ${total} identifiant${total > 1 ? "s" : ""}`;
  }

  // 4. État vide
  if (filteredEntries.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "empty-state";
    td.textContent =
      vaultEntries.length === 0
        ? "🗝️ Votre coffre est vide. Ajoutez votre premier identifiant."
        : "🔍 Aucun identifiant ne correspond à votre recherche.";
    tr.appendChild(td);
    entriesBody.appendChild(tr);
    return;
  }

  filteredEntries.forEach((entry, index) => {
    const tr = document.createElement("tr");

    const tdName = document.createElement("td");
    tdName.setAttribute("data-label", "Nom");
    tdName.textContent = entry.folder
      ? `[${entry.folder}] ${entry.name}`
      : entry.name;
    tr.appendChild(tdName);

    const tdUrl = document.createElement("td");
    tdUrl.setAttribute("data-label", "URL");
    if (entry.url) {
      const a = document.createElement("a");
      a.href = entry.url;
      a.textContent = entry.url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
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

    // ==========================================================================
    // 🔒 CELLULE DU MOT DE PASSE (MASQUAGE AUTO APRES 15 SECONDES)
    // ==========================================================================
    const tdPassword = document.createElement("td");
    tdPassword.setAttribute("data-label", "Mot de passe");

    tdPassword.style.display = "flex";
    tdPassword.style.alignItems = "center";
    tdPassword.style.justifyContent = "space-between";
    tdPassword.style.gap = "8px";

    const pwSpan = document.createElement("span");
    pwSpan.className = "hidden-password";
    pwSpan.textContent = "••••••••";

    pwSpan.style.flex = "1";
    pwSpan.style.wordBreak = "break-all";
    pwSpan.style.whiteSpace = "normal";

    let hideTimeout = null; // Stocke la minuterie propre à cette ligne

    const toggleBtn = document.createElement("button");
    toggleBtn.className = "toggle-pw-btn";
    toggleBtn.textContent = "👁️";
    toggleBtn.style.flexShrink = "0";

    toggleBtn.addEventListener("click", () => {
      if (pwSpan.textContent === "••••••••") {
        pwSpan.textContent = entry.password;
        pwSpan.className = "";
        showToast("👁️ Affichage temporaire (15 secondes)");

        // ⏳ Lance le compte à rebours de sécurité
        hideTimeout = setTimeout(() => {
          pwSpan.textContent = "••••••••";
          pwSpan.className = "hidden-password";
        }, 15000); // 15 secondes
      } else {
        // Si l'utilisateur reclique manuellement avant la fin des 15s
        if (hideTimeout) clearTimeout(hideTimeout);
        pwSpan.textContent = "••••••••";
        pwSpan.className = "hidden-password";
      }
    });

    tdPassword.appendChild(pwSpan);
    tdPassword.appendChild(toggleBtn);
    tr.appendChild(tdPassword);

    // ==========================================================================
    // 🛠️ ACTIONS (BOUTON COPIER SUPPRIMÉ POUR LA SÉCURITÉ)
    // ==========================================================================
    const tdActions = document.createElement("td");
    tdActions.setAttribute("data-label", "Actions");

    const editBtn = document.createElement("button");
    editBtn.textContent = "Éditer";
    editBtn.className = "action-btn edit";
    editBtn.style.background = "#6366f1";
    editBtn.addEventListener("click", () => {
      loadEntryIntoForm(vaultEntries.indexOf(entry));
    });

    const delBtn = document.createElement("button");
    delBtn.textContent = "Supprimer";
    delBtn.className = "action-btn delete";
    delBtn.addEventListener("click", async () => {
      if (confirm("Supprimer définitivement cet identifiant du cloud ?")) {
        if (entry.id) {
          await fetch(`${API_URL}/vault/${entry.id}`, {
            method: "DELETE",
            headers: { Authorization: `Bearer ${userToken}` },
          });
        }
        vaultEntries.splice(vaultEntries.indexOf(entry), 1);
        renderEntries(searchInput.value);
        showToast("Supprimé.");
      }
    });

    tdActions.appendChild(editBtn); // Uniquement Éditer
    tdActions.appendChild(delBtn); // Uniquement Supprimer
    tr.appendChild(tdActions);
    entriesBody.appendChild(tr);
  });
}

function handleLogout() {
  // 1. 🛠️ NETTOYAGE : Supprime immédiatement la session du navigateur (sessionStorage)
  sessionStorage.removeItem("sword_session");

  // 2. Réinitialisation des variables globales en mémoire volatile
  userToken = null;
  vaultKey = null;
  vaultEntries = [];

  // 3. Destruction des écouteurs d'inactivité (Auto-lock)
  destroySecurityListeners();

  // 4. Gestion de l'interface visuelle (Bascule d'écran)
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
  entryFolderInput.value = "";
  submitEntryBtn.textContent = "Enregistrer";

  if (document.getElementById("password-strength")) {
    document.getElementById("password-strength").className = "strength-bar";
  }

  // Ferme automatiquement la modale et réinitialise le bouton d'ouverture
  entryForm.classList.add("hidden");
  toggleFormBtn.textContent = "➕ Ajouter";
  if (entryFormTitle) entryFormTitle.textContent = "Ajouter un identifiant";
}

function loadEntryIntoForm(index) {
  const entry = vaultEntries[index];
  entryIdInput.value = entry.id || "";

  entryNameInput.value = entry.name || "";
  entryUrlInput.value = entry.url || "";
  entryUsernameInput.value = entry.username || "";
  entryPasswordInput.value = entry.password || "";
  entryFolderInput.value = entry.folder || "";

  submitEntryBtn.textContent = "Mettre à jour";
  checkPasswordStrengthVisual(entry.password || "");

  // Ouvre la modale en mode édition
  entryForm.classList.remove("hidden");
  if (entryFormTitle) entryFormTitle.textContent = "Modifier l'identifiant";
}

// ÉVÈNEMENT
unlockBtn.addEventListener("click", handleLogin);
registerBtn.addEventListener("click", handleRegister);
lockBtn.addEventListener("click", handleLogout);
searchInput.addEventListener("input", () => {
  renderEntries(searchInput.value);
});

entryForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  const inputPassword = entryPasswordInput.value;
  let pendingWarning = null; // Permet de stocker la phrase drôle temporairement

  // 1. VÉRIFICATION DE COMPROMISSION ROCKYOU VIA API (NON-BLOQUANT)
  if (inputPassword) {
    try {
      const hash = await sha1(inputPassword);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      if (res.ok) {
        const text = await res.text();
        const isPwned = text
          .split("\n")
          .some((line) => line.startsWith(suffix));

        if (isPwned) {
          strengthBar.className = "strength-bar weak";
          // On garde la phrase au chaud pour l'afficher juste après la synchronisation
          pendingWarning =
            trollMessages[Math.floor(Math.random() * trollMessages.length)];
        }
      }
    } catch (err) {
      console.error("Impossible de valider la blacklist :", err);
    }
  }

  // 2. LOGIQUE DE CHIFFREMENT ET D'ENVOI
  submitEntryBtn.disabled = true;
  const entryId = entryIdInput.value;
  const currentFolder = entryFolderInput.value.trim() || null;

  let rawUrl = entryUrlInput.value.trim();
  if (rawUrl && !/^https?:\/\//i.test(rawUrl)) {
    rawUrl = "https://" + rawUrl;
  }

  const entryDataClear = {
    url: rawUrl,
    username: entryUsernameInput.value.trim(),
    password: inputPassword,
  };
  const label = entryNameInput.value.trim();
  if (!label) {
    submitEntryBtn.disabled = false;
    return alert("Nom requis.");
  }

  try {
    const encryptedData = await encryptString(
      JSON.stringify(entryDataClear),
      vaultKey,
    );
    let res;

    if (entryId) {
      // MODE ÉDITION
      res = await fetch(`${API_URL}/vault/${entryId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({
          type: "login",
          label,
          encryptedData,
          folder: currentFolder,
        }),
      });
    } else {
      // MODE CRÉATION
      res = await fetch(`${API_URL}/vault`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({
          type: "login",
          label,
          encryptedData,
          folder: currentFolder,
        }),
      });
    }

    if (res.ok) {
      await fetchVaultItems();

      resetForm();
      renderEntries(searchInput.value);

      // On affiche d'abord la réussite de l'enregistrement
      showToast(
        entryId
          ? "🔄 Identifiant mis à jour !"
          : "💾 Synchronisé avec le Cloud.",
      );

      // Si le mot de passe était compromis, on déclenche la phrase drôle 3.5 secondes après
      if (pendingWarning) {
        setTimeout(() => {
          showToast(`⚠️ Attention ! ${pendingWarning}`);
        }, 3500);
      }
    } else {
      alert("Échec de synchronisation.");
    }
  } catch (err) {
    alert("Erreur technique.");
  } finally {
    submitEntryBtn.disabled = false;
  }
});

// ==========================================================================
// 🎲 ÉCOUTEUR DU BOUTON GÉNÉRER (VERSION SÉCURISÉE)
// ==========================================================================
generateBtn.addEventListener("click", () => {
  entryPasswordInput.value = (() => {
    // 1. Base de lettres indispensables
    let allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // 2. Récupération des éléments HTML avec sécurité s'ils n'existent pas encore
    const chkNumbers = document.getElementById("gen-numbers");
    const chkSpecials = document.getElementById("gen-specials");

    // 3. On ajoute les chiffres et spéciaux si les cases sont cochées
    // (ou par défaut si les éléments n'existent pas dans ton HTML)
    if (!chkNumbers || chkNumbers.checked) {
      allowedChars += "0123456789";
    }
    if (!chkSpecials || chkSpecials.checked) {
      allowedChars += "()_-,?:§!@#$%^&*=+";
    }

    // 4. Génération cryptographique robuste
    let pw = "";
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);

    for (let i = 0; i < 16; i++) {
      pw += allowedChars[array[i] % allowedChars.length];
    }
    return pw;
  })();

  // 5. Mise à jour de la jauge visuelle
  setTimeout(() => {
    if (typeof checkPasswordStrengthVisual === "function") {
      checkPasswordStrengthVisual(entryPasswordInput.value);
    }
  }, 10);

  showToast("🎲 Mot de passe personnalisé généré.");
});
resetFormBtn.addEventListener("click", resetForm);

// ==========================================================================
// 🛡️ ANALYSEUR DE FORCE (MÉTHODE LOCALE SANS NOTIFICATION INTEMPÈSTIVE)
// ==========================================================================
const strengthBar = document.getElementById("password-strength");

const trollMessages = [
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
  "Même une attaque par dictionnaire hors-ligne plierait l'affaire avant que j'aie le temps de cligner des yeux. ⚡",
];

// Fonction pour calculer le score classique (visuel uniquement pendant la saisie)
function checkPasswordStrengthVisual(password) {
  strengthBar.className = "strength-bar";
  if (!password) return;

  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 14) score++;
  if (/\d/.test(password)) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (score <= 2) strengthBar.classList.add("weak");
  else if (score <= 4) strengthBar.classList.add("medium");
  else strengthBar.classList.add("strong");
}

// Fonction asynchrone isolée pour calculer le SHA-1
async function sha1(str) {
  const buf = new TextEncoder().encode(str);
  const hashBuf = await crypto.subtle.digest("SHA-1", buf);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

// Écouteur sur la saisie : met à jour la couleur du bandeau sans harceler avec des toasts
entryPasswordInput.addEventListener("input", (e) => {
  checkPasswordStrengthVisual(e.target.value);
});

// ==========================================================================
// 🔄 LOGIQUE D'AFFICHAGE DU FORMULAIRE (TOGGLE)
// ==========================================================================
toggleFormBtn.addEventListener("click", () => {
  if (entryForm.classList.contains("hidden")) {
    entryForm.classList.remove("hidden");
    toggleFormBtn.textContent = "➕ Ajouter";
    if (entryFormTitle) entryFormTitle.textContent = "Ajouter un identifiant";
    entryNameInput.focus();
  } else {
    resetForm();
  }
});

if (modalCloseBtn) {
  modalCloseBtn.addEventListener("click", resetForm);
}
entryForm.addEventListener("click", (e) => {
  if (e.target === entryForm) resetForm();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !entryForm.classList.contains("hidden")) {
    resetForm();
  }
});

if (toggleMasterPwBtn) {
  toggleMasterPwBtn.addEventListener("click", () => {
    const isHidden = masterPasswordInput.type === "password";
    masterPasswordInput.type = isHidden ? "text" : "password";
    toggleMasterPwBtn.textContent = isHidden ? "🙈" : "👁️";
    toggleMasterPwBtn.setAttribute(
      "aria-label",
      isHidden ? "Masquer le mot de passe" : "Afficher le mot de passe",
    );
  });
}

// ==========================================================================
// 🔄 RESTAURATION AUTOMATIQUE DE SESSION AU REFRESH (F5)
// ==========================================================================
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
      "raw",
      base64ToBuf(sessionData.keyB64),
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
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

// ==========================================================================
// 📥 EXPORTATION DU COFFRE-FORT EN FORMAT CSV
// ==========================================================================
if (exportBtn) {
  const confirmModal = document.getElementById("confirm-modal");
  const confirmActionBtn = document.getElementById("confirm-action-btn");
  const confirmCancelBtn = document.getElementById("confirm-cancel-btn");
  const confirmCancelCross = document.getElementById("confirm-cancel-cross");

  const closeConfirm = () => {
    confirmModal.classList.add("hidden");
  };

  exportBtn.addEventListener("click", () => {
    if (vaultEntries.length === 0) {
      return alert("Votre coffre-fort est vide. Rien à exporter !");
    }
    confirmModal.classList.remove("hidden");
  });

  confirmActionBtn.addEventListener("click", () => {
    closeConfirm();
    const headers = ["Nom", "URL", "Identifiant", "Mot de passe", "Dossier"];
    const csvRows = [
      headers.join(","),
      ...vaultEntries.map((entry) => {
        return [
          `"${(entry.name || "").replace(/"/g, '""')}"`,
          `"${(entry.url || "").replace(/"/g, '""')}"`,
          `"${(entry.username || "").replace(/"/g, '""')}"`,
          `"${(entry.password || "").replace(/"/g, '""')}"`,
          `"${(entry.folder || "Sans dossier").replace(/"/g, '""')}"`,
        ].join(",");
      }),
    ];

    const csvContent = "\uFEFF" + csvRows.join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);

    link.setAttribute("href", url);
    link.setAttribute(
      "download",
      `SwordManager_Export_${new Date().toISOString().split("T")[0]}.csv`,
    );
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast("📥 Coffre-fort exporté avec succès !");
  });

  confirmCancelBtn.addEventListener("click", closeConfirm);
  confirmCancelCross.addEventListener("click", closeConfirm);
  confirmModal.addEventListener("click", (e) => {
    if (e.target === confirmModal) closeConfirm();
  });
}

if (folderFilter) {
  folderFilter.addEventListener("change", () => {
    renderEntries(searchInput.value);
  });
}

// ==========================================================================
// 📊 GENERATION ET ANALYSE DU RAPPORT DE SECURITE
// ==========================================================================
const reportBtn = document.getElementById("report-btn");
const reportModal = document.getElementById("report-modal");
const reportCloseBtn = document.getElementById("report-close-btn");
const weakCountEl = document.getElementById("weak-count");
const pwnedCountEl = document.getElementById("pwned-count");
const reportListPwnedEl = document.getElementById("report-list-pwned");
const reportListWeakEl = document.getElementById("report-list-weak");

if (reportBtn) {
  reportBtn.addEventListener("click", async () => {
    if (vaultEntries.length === 0) {
      return alert("Aucune donnée à analyser. Votre coffre est vide !");
    }

    reportListPwnedEl.innerHTML = "<p style='color: var(--color-text-muted);'>Analyse des fuites...</p>";
    reportListWeakEl.innerHTML = "<p style='color: var(--color-text-muted);'>Analyse de la force...</p>";
    reportModal.classList.remove("hidden");

    let weakCounter = 0;
    let pwnedCounter = 0;
    let htmlPwnedItems = "";
    let htmlWeakItems = "";

    for (const entry of vaultEntries) {
      let isWeak = false;
      let isPwned = false;
      let weakReasons = [];
      const pwd = entry.password || "";

      if (pwd.length < 10) {
        isWeak = true;
        weakReasons.push("Trop court (< 10 car.)");
      }
      if (!/[^A-Za-z0-9]/.test(pwd) || !/\d/.test(pwd)) {
        isWeak = true;
        weakReasons.push("Manque de chiffres/spéciaux");
      }

      if (pwd) {
        try {
          const hash = await sha1(pwd);
          const prefix = hash.slice(0, 5);
          const suffix = hash.slice(5);
          const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
          if (res.ok) {
            const text = await res.text();
            isPwned = text.split("\n").some((line) => line.startsWith(suffix));
          }
        } catch (e) {
          console.error(e);
        }
      }

      const makeRow = (reasonsColor, reasonsText) => `
        <div style="border-bottom: 1px solid var(--color-border); padding: 8px 0; display: flex; justify-content: space-between; align-items: center; gap: 10px;">
          <div style="flex: 1; min-width: 0;">
            <strong style="display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${entry.name}</strong>
            <span style="color: var(--color-text-muted); font-size: 0.8rem;">${entry.username || "Sans identifiant"}</span>
            <div style="font-size: 0.75rem; color: ${reasonsColor}; margin-top: 2px;">${reasonsText}</div>
          </div>
          <button class="action-btn edit" style="background: #6366f1; padding: 4px 8px; font-size: 0.72rem; flex-shrink: 0;" onclick="document.getElementById('report-modal').classList.add('hidden'); loadEntryIntoForm(${vaultEntries.indexOf(entry)});">Corriger</button>
        </div>
      `;

      if (isPwned) {
        pwnedCounter++;
        htmlPwnedItems += makeRow("#f87171", "❌ Trouvé dans des fuites publiques !");
      }
      if (isWeak) {
        weakCounter++;
        htmlWeakItems += makeRow("#fbbf24", `⚠️ ${weakReasons.join(" • ")}`);
      }
    }

    weakCountEl.textContent = weakCounter;
    pwnedCountEl.textContent = pwnedCounter;
    reportListPwnedEl.innerHTML = htmlPwnedItems || "<p style='color: var(--color-success); font-size: 0.85rem; text-align: center; margin: 5px 0;'>✅ Aucun mot de passe compromis !</p>";
    reportListWeakEl.innerHTML = htmlWeakItems || "<p style='color: var(--color-success); font-size: 0.85rem; text-align: center; margin: 5px 0;'>✅ Tous vos mots de passe sont robustes !</p>";
  });

  if (reportCloseBtn) {
    reportCloseBtn.addEventListener("click", () => reportModal.classList.add("hidden"));
  }
  reportModal.addEventListener("click", (e) => {
    if (e.target === reportModal) reportModal.classList.add("hidden");
  });
}

// ==========================================================================
// 💡 MODALE DU GUIDE DES BONNES PRATIQUES
// ==========================================================================
const guideBtn = document.getElementById("guide-btn");
const guideModal = document.getElementById("guide-modal");
const guideOkBtn = document.getElementById("guide-ok-btn"); // 🛠️ Correction ID ici pour correspondre au HTML

if (guideBtn && guideModal) {
  guideBtn.addEventListener("click", () => {
    guideModal.classList.remove("hidden");
  });

  if (guideOkBtn) {
    guideOkBtn.addEventListener("click", () => guideModal.classList.add("hidden"));
  }
  
  // Bonus : Permet aussi de fermer en cliquant à côté de la modale guide
  guideModal.addEventListener("click", (e) => {
    if (e.target === guideModal) guideModal.classList.add("hidden");
  });
}
