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

// Envoie un événement d'activité au backend (best-effort, ne bloque jamais l'UI)
function logActivityEvent(action, detail) {
  if (!userToken) return;
  fetch(`${API_URL}/activity`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${userToken}`,
    },
    body: JSON.stringify({ action, detail }),
  }).catch((err) => console.error("[Activity Log Error]:", err));
}

// ==========================================================================
// 🚨 GESTIONNAIRE D'ERREURS D'API INTELLIGENT (DEV VS PROD)
// ==========================================================================
function handleApiError(error, errorElement) {
  console.error("[API Error]:", error);

  // Si l'erreur est un échec de fetch (réseau coupé, serveur éteint, crash VM)
  if (error instanceof TypeError && error.message.includes("fetch")) {
    const isLocal =
      window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1";

    if (isLocal) {
      errorElement.textContent =
        "🔌 Impossible de joindre l'API locale. Lancez votre serveur Node.js sur le port 3000.";
    } else {
      errorElement.textContent =
        "☁️ Le serveur Cloud est injoignable. L'instance est peut-être arrêtée ou en cours de maintenance.";
    }
  } else {
    // Erreurs diverses (JSON corrompu, problème crypto, etc.)
    errorElement.textContent =
      "⚠️ Une erreur technique inattendue est survenue.";
  }
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
    handleApiError(e, masterError);
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
      masterError.style.color = "#f97373";

      // On récupère la valeur de l'erreur renvoyée par le backend (authController.js)
      const errType = data && data.error ? data.error : "";

      // Si le backend renvoie "AuthenticationError" (l'email n'existe pas ou le mdp est faux)
      if (errType === "AuthenticationError") {
        masterError.textContent =
          "Aucun compte n'existe avec cet email, ou vos identifiants sont incorrects. Veuillez en créer un !";
      } else {
        // Pour les autres erreurs (ex: ValidationError, InternalServerError ou erreur locale)
        masterError.textContent = data.error || "Identifiants erronés.";
      }
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
  // ==========================================================================
  // 🗑️ GESTION DYNAMIQUE DU BOUTON DE SUPPRESSION DE DOSSIER
  // ==========================================================================
  let deleteFolderBtn = document.getElementById("delete-folder-btn");

  // Si le bouton n'existe pas encore dans ton HTML, on le crée dynamiquement à côté du filtre
  if (!deleteFolderBtn && folderFilter) {
    deleteFolderBtn = document.createElement("button");
    deleteFolderBtn.id = "delete-folder-btn";
    deleteFolderBtn.className = "action-btn delete";
    deleteFolderBtn.style.marginLeft = "10px";
    deleteFolderBtn.style.padding = "6px 12px";
    deleteFolderBtn.style.fontSize = "0.85rem";
    // On l'insère juste après le select du filtre
    folderFilter.parentNode.insertBefore(
      deleteFolderBtn,
      folderFilter.nextSibling,
    );
  }

  // On affiche le bouton UNIQUEMENT si un vrai dossier personnalisé est sélectionné
  if (selectedFolder && selectedFolder !== "sans-dossier") {
    deleteFolderBtn.textContent = `🗑️ Supprimer le dossier "${selectedFolder}"`;
    deleteFolderBtn.style.display = "inline-block";

    // On branche l'action de suppression (on nettoie l'ancien onclick avant)
    deleteFolderBtn.onclick = () => {
      handleDeleteFolder(selectedFolder);
    };
  } else if (deleteFolderBtn) {
    deleteFolderBtn.style.display = "none";
  }

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
    // 🛡️ MASQUER LES DOSSIERS VIDES DU TABLEAU
    if (entry.name && entry.name.startsWith("[Dossier Vide]")) {
      return false;
    }

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

    // 🏷️ COLONNE NOM AVEC ACCÈS DIRECT AU DOSSIER
    const tdName = document.createElement("td");
    tdName.setAttribute("data-label", "Nom");

    const nameWrapper = document.createElement("div");
    nameWrapper.className = "name-wrapper";

    // On utilise directement la vraie variable de dossier de ton identifiant !
    if (entry.folder) {
      const folderBadge = document.createElement("span");
      folderBadge.className = "folder-badge";
      folderBadge.textContent = entry.folder;
      nameWrapper.appendChild(folderBadge);
    }

    // Le titre de l'identifiant reste intact
    const nameTitle = document.createElement("span");
    nameTitle.className = "entry-title";
    nameTitle.textContent = entry.name || "";
    nameWrapper.appendChild(nameTitle);

    tdName.appendChild(nameWrapper);
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
        logActivityEvent("password_revealed", entry.name || null);

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

    const copyPwBtn = document.createElement("button");
    copyPwBtn.className = "toggle-pw-btn";
    copyPwBtn.textContent = "📋";
    copyPwBtn.title = "Copier le mot de passe";
    copyPwBtn.style.flexShrink = "0";

    copyPwBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(entry.password).then(() => {
        showToast("📋 Mot de passe copié !");
        logActivityEvent("password_copied", entry.name || null);
      });
    });

    tdPassword.appendChild(pwSpan);
    tdPassword.appendChild(copyPwBtn);
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

    // ==========================================================================
    // 🛠️ ACTIONS (BOUTON SUPPRIMER PROPRE AVEC FLAGGING SÉCURISÉ)
    // ==========================================================================
    const delBtn = document.createElement("button");
    delBtn.textContent = "Supprimer";
    delBtn.className = "action-btn delete";

    delBtn.addEventListener("click", () => {
      const confirmModal = document.getElementById("confirm-modal");
      const confirmActionBtn = document.getElementById("confirm-action-btn");
      const confirmCancelBtn = document.getElementById("confirm-cancel-btn");
      const confirmCancelCross = document.getElementById(
        "confirm-cancel-cross",
      );

      if (!confirmModal || !confirmActionBtn) return;

      // 1. 🛡️ SÉCURITÉ : On bascule la modale partagée en mode suppression
      confirmActionBtn.dataset.mode = "delete";
      confirmActionBtn.disabled = false;

      // 2. Personnalisation visuelle
      const confirmBody = confirmModal.querySelector(".confirm-body");
      if (confirmBody) {
        confirmBody.innerHTML = `Êtes-vous sûr de vouloir supprimer définitivement l'identifiant <strong>${entry.name || "cet élément"}</strong> du cloud ?`;
      }
      confirmActionBtn.textContent = "Supprimer";

      // Affichage de la modale
      confirmModal.classList.remove("hidden");

      // 3. Fonctions de fermeture propre
      const closeDeleteModal = () => {
        confirmModal.classList.add("hidden");
        confirmActionBtn.onclick = null;
        // 🔓 Nettoyage du mode pour rendre le bouton à l'exportation
        delete confirmActionBtn.dataset.mode;
        confirmActionBtn.textContent = "Confirmer";
      };

      if (confirmCancelBtn) confirmCancelBtn.onclick = closeDeleteModal;
      if (confirmCancelCross) confirmCancelCross.onclick = closeDeleteModal;
      confirmModal.onclick = (e) => {
        if (e.target === confirmModal) closeDeleteModal();
      };

      // 4. Logique d'exécution de la suppression
      confirmActionBtn.onclick = async (e) => {
        e.preventDefault();

        try {
          confirmActionBtn.disabled = true;
          confirmActionBtn.textContent = "Suppression...";

          if (entry.id) {
            await fetch(`${API_URL}/vault/${entry.id}`, {
              method: "DELETE",
              headers: { Authorization: `Bearer ${userToken}` },
            });
          }

          vaultEntries.splice(vaultEntries.indexOf(entry), 1);
          closeDeleteModal();
          renderEntries(searchInput.value);
          showToast("🗑️ Supprimé.");
        } catch (err) {
          console.error(err);
          alert("Erreur technique lors de la suppression.");
        } finally {
          confirmActionBtn.disabled = false;
        }
      };
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

// ==========================================================================
// 📁 LOGIQUE DE SUPPRESSION DE DOSSIER (VERSION MODALE SÉCURISÉE)
// ==========================================================================
async function handleDeleteFolder(folderName) {
  const confirmModal = document.getElementById("confirm-modal");
  const confirmActionBtn = document.getElementById("confirm-action-btn");
  const confirmCancelBtn = document.getElementById("confirm-cancel-btn");
  const confirmCancelCross = document.getElementById("confirm-cancel-cross");

  if (!confirmModal || !confirmActionBtn) return;

  // 1. 🛡️ SÉCURITÉ : Passage de la modale en mode suppression de dossier
  confirmActionBtn.dataset.mode = "delete-folder";
  confirmActionBtn.disabled = false;

  // 2. Personnalisation visuelle du texte de la modale
  const confirmBody = confirmModal.querySelector(".confirm-body");
  if (confirmBody) {
    confirmBody.innerHTML = `Voulez-vous vraiment supprimer le dossier <strong>${folderName}</strong> ?<br><br><span style="color: #fbbf24;">⚠️ Les mots de passe à l'intérieur ne seront pas supprimés, ils seront simplement déplacés dans "Sans dossier".</span>`;
  }
  confirmActionBtn.textContent = "Supprimer le dossier";

  // Affichage de la modale
  confirmModal.classList.remove("hidden");

  // 3. Fonctions de fermeture propre
  const closeFolderDeleteModal = () => {
    confirmModal.classList.add("hidden");
    confirmActionBtn.onclick = null;
    // Nettoyage du mode pour rendre le bouton aux autres fonctionnalités (comme l'export)
    delete confirmActionBtn.dataset.mode;
    confirmActionBtn.textContent = "Confirmer";
  };

  if (confirmCancelBtn) confirmCancelBtn.onclick = closeFolderDeleteModal;
  if (confirmCancelCross) confirmCancelCross.onclick = closeFolderDeleteModal;
  confirmModal.onclick = (e) => {
    if (e.target === confirmModal) closeFolderDeleteModal();
  };

  // 4. Exécution de la suppression lors du clic sur le bouton de confirmation
  confirmActionBtn.onclick = async (e) => {
    e.preventDefault();

    try {
      confirmActionBtn.disabled = true;
      confirmActionBtn.textContent = "Suppression du dossier...";
      showToast("⏳ Traitement du dossier...");

      // On filtre les éléments qui appartiennent à ce dossier
      const entriesInFolder = vaultEntries.filter(
        (entry) => entry.folder === folderName,
      );

      // On sépare le placeholder "Dossier Vide" des vrais identifiants
      const placeholderEntry = entriesInFolder.find(
        (entry) => entry.name && entry.name.startsWith("[Dossier Vide]"),
      );
      const realEntries = entriesInFolder.filter(
        (entry) => !entry.name || !entry.name.startsWith("[Dossier Vide]"),
      );

      // ÉTAPE 1 : Mettre à jour les vrais identifiants pour retirer le dossier (folder = null)
      for (const entry of realEntries) {
        const entryDataClear = {
          url: entry.url,
          username: entry.username,
          password: entry.password,
        };

        const encryptedData = await encryptString(
          JSON.stringify(entryDataClear),
          vaultKey,
        );

        await fetch(`${API_URL}/vault/${entry.id}`, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${userToken}`,
          },
          body: JSON.stringify({
            type: "login",
            label: entry.name,
            encryptedData,
            folder: null,
          }),
        });
      }

      // ÉTAPE 2 : Supprimer physiquement le placeholder de dossier vide
      if (placeholderEntry && placeholderEntry.id) {
        await fetch(`${API_URL}/vault/${placeholderEntry.id}`, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${userToken}` },
        });
      }

      // ÉTAPE 3 : Synchronisation et fermeture
      await fetchVaultItems();

      if (folderFilter) {
        folderFilter.value = "";
      }

      closeFolderDeleteModal();
      renderEntries();
      showToast(`📁 Dossier "${folderName}" supprimé avec succès !`);
    } catch (err) {
      console.error("Erreur lors de la suppression du dossier :", err);
      showToast("❌ Une erreur est survenue.");
    } finally {
      confirmActionBtn.disabled = false;
    }
  };
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
// 🎲 ÉCOUTEUR DU BOUTON GÉNÉRER (VERSION CRYPTO SÛRE AVEC PRÉSENCE GARANTIE)
// ==========================================================================
generateBtn.addEventListener("click", () => {
  entryPasswordInput.value = (() => {
    // 1. Définition des différents pools de caractères
    const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789";
    const specials = "()_-,?:§!@#$%^&*=+";

    const chkNumbers = document.getElementById("gen-numbers");
    const chkSpecials = document.getElementById("gen-specials");

    const useNumbers = !chkNumbers || chkNumbers.checked;
    const useSpecials = !chkSpecials || chkSpecials.checked;

    // Notre pool global de secours
    let allowedChars = alpha;
    if (useNumbers) allowedChars += numbers;
    if (useSpecials) allowedChars += specials;

    let pwArray = [];

    // Fonction interne de tirage cryptographique d'un seul caractère dans un sous-ensemble
    const getRandomCharFromSet = (charSet) => {
      const len = charSet.length;
      const maxValidValue = 256 - (256 % len);
      const singleRandomValue = new Uint8Array(1);
      
      while (true) {
        crypto.getRandomValues(singleRandomValue);
        const randomValue = singleRandomValue[0];
        if (randomValue < maxValidValue) {
          return charSet[randomValue % len];
        }
      }
    };

    // 2. ÉTAPE DE GARANTIE : On pioche au moins un caractère requis de chaque type coché
    pwArray.push(getRandomCharFromSet(alpha)); // Au moins une lettre
    if (useNumbers) {
      pwArray.push(getRandomCharFromSet(numbers)); // Au moins un chiffre garanti !
    }
    if (useSpecials) {
      pwArray.push(getRandomCharFromSet(specials)); // Au moins un caractère spécial garanti !
    }

    // 3. ÉTAPE DE REMPLISSAGE : On complète pour atteindre 16 caractères au total
    while (pwArray.length < 16) {
      pwArray.push(getRandomCharFromSet(allowedChars));
    }

    // 4. ÉTAPE DE MÉLANGE (Fisher-Yates cryptographique)
    // Indispensable pour que le chiffre ou caractère spécial obligatoire ne soit pas toujours au début !
    const randomBuffer = new Uint32Array(pwArray.length);
    crypto.getRandomValues(randomBuffer);

    for (let i = pwArray.length - 1; i > 0; i--) {
      // Tirage d'un index d'échange sans biais de modulo
      const j = randomBuffer[i] % (i + 1);
      // Échange des éléments
      const temp = pwArray[i];
      pwArray[i] = pwArray[j];
      pwArray[j] = temp;
    }

    return pwArray.join("");
  })();

  // Mise à jour de la jauge visuelle de force
  setTimeout(() => {
    if (typeof checkPasswordStrengthVisual === "function") {
      checkPasswordStrengthVisual(entryPasswordInput.value);
    }
  }, 10);

  showToast("🎲 Mot de passe robuste et personnalisé généré.");
});

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

// ==========================================================================
// ❌ ÉCOUTEURS DE FERMETURE DU FORMULAIRE (ANNULER & CROIX)
// ==========================================================================

// 1. Branchement de la croix (✕) de fermeture spécifique au formulaire
if (entryForm) {
  const formCloseCross = entryForm.querySelector(".modal-close");
  if (formCloseCross) {
    formCloseCross.addEventListener("click", (e) => {
      e.preventDefault(); // Évite tout comportement par défaut
      resetForm();
    });
  }
}

// 2. Branchement du bouton "Annuler" (reset-form-btn)
if (resetFormBtn) {
  resetFormBtn.addEventListener("click", (e) => {
    e.preventDefault(); // Évite absolument la soumission/rechargement accidentel !
    resetForm();
  });
}

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

    // 🔄 REINITIALISATION DES TEXTES DE LA MODALE POUR L'EXPORT
    const confirmBody = confirmModal.querySelector(".confirm-body");
    if (confirmBody) {
      confirmBody.innerHTML =
        "Êtes-vous sûr de vouloir exporter l'intégralité de vos identifiants en clair dans un fichier CSV ?";
    }
    confirmActionBtn.textContent = "Exporter en clair";

    confirmModal.classList.remove("hidden");
  });

  confirmActionBtn.addEventListener("click", () => {
    // ⛔ Si la modale est utilisée pour un processus de suppression (identifiant ou dossier), on bloque l'export !
    if (
      confirmActionBtn.dataset.mode === "delete" ||
      confirmActionBtn.dataset.mode === "delete-folder"
    ) {
      return;
    }
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
// 🕓 HISTORIQUE D'ACTIVITÉ DU COMPTE
// ==========================================================================
const activityBtn = document.getElementById("activity-btn");
const activityModal = document.getElementById("activity-modal");
const activityCloseBtn = document.getElementById("activity-close-btn");
const activityListEl = document.getElementById("activity-list");

const ACTIVITY_LABELS = {
  login: { icon: "🔑", text: "Connexion" },
  item_created: { icon: "➕", text: "Identifiant ajouté" },
  item_updated: { icon: "✏️", text: "Identifiant modifié" },
  item_deleted: { icon: "🗑️", text: "Identifiant supprimé" },
  password_copied: { icon: "📋", text: "Mot de passe copié" },
  password_revealed: { icon: "👁️", text: "Mot de passe affiché" },
};

function closeActivityModal() {
  if (activityModal) activityModal.classList.add("hidden");
}

if (activityBtn) {
  activityBtn.addEventListener("click", async () => {
    activityListEl.innerHTML =
      "<p style='color: var(--color-text-muted);'>Chargement de l'historique...</p>";
    activityModal.classList.remove("hidden");

    try {
      const res = await fetch(`${API_URL}/activity`, {
        headers: { Authorization: `Bearer ${userToken}` },
      });
      if (!res.ok) throw new Error("Failed to load activity log.");

      const logs = await res.json();
      activityListEl.innerHTML = "";

      if (logs.length === 0) {
        const empty = document.createElement("p");
        empty.style.color = "var(--color-text-muted)";
        empty.textContent = "Aucune activité enregistrée pour le moment.";
        activityListEl.appendChild(empty);
        return;
      }

      logs.forEach((log) => {
        const meta = ACTIVITY_LABELS[log.action] || {
          icon: "•",
          text: log.action,
        };

        const row = document.createElement("div");
        row.style.borderBottom = "1px solid var(--color-border)";
        row.style.padding = "8px 0";
        row.style.display = "flex";
        row.style.justifyContent = "space-between";
        row.style.alignItems = "center";
        row.style.gap = "10px";

        const infoDiv = document.createElement("div");
        infoDiv.style.flex = "1";
        infoDiv.style.minWidth = "0";

        const strongAction = document.createElement("strong");
        strongAction.style.display = "block";
        strongAction.textContent = `${meta.icon} ${meta.text}${log.detail ? " — " + log.detail : ""}`;

        const spanDate = document.createElement("span");
        spanDate.style.color = "var(--color-text-muted)";
        spanDate.style.fontSize = "0.8rem";
        spanDate.textContent = new Date(log.createdAt).toLocaleString(
          "fr-FR",
        );

        infoDiv.appendChild(strongAction);
        infoDiv.appendChild(spanDate);

        const spanIp = document.createElement("span");
        spanIp.style.color = "var(--color-text-muted)";
        spanIp.style.fontSize = "0.8rem";
        spanIp.style.whiteSpace = "nowrap";
        spanIp.textContent = log.ip || "";

        row.appendChild(infoDiv);
        row.appendChild(spanIp);
        activityListEl.appendChild(row);
      });
    } catch (err) {
      console.error(err);
      activityListEl.innerHTML =
        "<p style='color: var(--color-danger);'>Impossible de charger l'historique.</p>";
    }
  });
}

if (activityCloseBtn) activityCloseBtn.addEventListener("click", closeActivityModal);
if (activityModal) {
  activityModal.addEventListener("click", (e) => {
    if (e.target === activityModal) closeActivityModal();
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

    // 1. Initialisation des états d'attente (Les messages bruts statiques restent en innerHTML, aucun danger ici)
    reportListPwnedEl.innerHTML =
      "<p style='color: var(--color-text-muted);'>Analyse des fuites...</p>";
    reportListWeakEl.innerHTML =
      "<p style='color: var(--color-text-muted);'>Analyse de la force...</p>";
    reportModal.classList.remove("hidden");

    let weakCounter = 0;
    let pwnedCounter = 0;

    // Fonction interne sécurisée pour injecter une ligne sans utiliser innerHTML
    const appendReportRow = (container, entry, reasonsColor, reasonsText) => {
      const row = document.createElement("div");
      row.style.borderBottom = "1px solid var(--color-border)";
      row.style.padding = "8px 0";
      row.style.display = "flex";
      row.style.justifyContent = "space-between";
      row.style.alignItems = "center";
      row.style.gap = "10px";

      const infoDiv = document.createElement("div");
      infoDiv.style.flex = "1";
      infoDiv.style.minWidth = "0";

      const strongName = document.createElement("strong");
      strongName.style.display = "block";
      strongName.style.overflow = "hidden";
      strongName.style.textOverflow = "ellipsis";
      strongName.style.whiteSpace = "nowrap";
      strongName.textContent = entry.name || ""; // 🛡️ Échappement XSS automatique via textContent

      const spanUser = document.createElement("span");
      spanUser.style.color = "var(--color-text-muted)";
      spanUser.style.fontSize = "0.8rem";
      spanUser.textContent = entry.username || "Sans identifiant"; // 🛡️ Échappement XSS automatique via textContent

      const reasonsDiv = document.createElement("div");
      reasonsDiv.style.fontSize = "0.75rem";
      reasonsDiv.style.color = reasonsColor;
      reasonsDiv.textContent = reasonsText;

      infoDiv.appendChild(strongName);
      infoDiv.appendChild(spanUser);
      infoDiv.appendChild(reasonsDiv);

      const fixBtn = document.createElement("button");
      fixBtn.className = "action-btn edit";
      fixBtn.style.background = "#6366f1";
      fixBtn.style.padding = "4px 8px";
      fixBtn.style.fontSize = "0.72rem";
      fixBtn.style.flexShrink = "0";
      fixBtn.textContent = "Corriger";
      fixBtn.addEventListener("click", () => {
        reportModal.classList.add("hidden");
        loadEntryIntoForm(vaultEntries.indexOf(entry));
      });

      row.appendChild(infoDiv);
      row.appendChild(fixBtn);
      container.appendChild(row);
    };

    // 2. Boucle d'analyse des identifiants
    for (const entry of vaultEntries) {
      // 🛡️ IGNORER LES DOSSIERS VIDES DANS L'ANALYSE DE SÉCURITÉ
      if (entry.name && entry.name.startsWith("[Dossier Vide]")) {
        continue; // Passe directement à l'élément suivant sans l'analyser
      }
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
          const res = await fetch(
            `https://api.pwnedpasswords.com/range/${prefix}`,
          );
          if (res.ok) {
            const text = await res.text();
            isPwned = text.split("\n").some((line) => line.startsWith(suffix));
          }
        } catch (e) {
          console.error(e);
        }
      }

      // 3. Traitement et injection dynamique sécurisée
      if (isPwned) {
        pwnedCounter++;
        // Au premier élément trouvé, on nettoie le texte d'attente "Analyse des fuites..."
        if (pwnedCounter === 1) reportListPwnedEl.innerHTML = "";
        appendReportRow(
          reportListPwnedEl,
          entry,
          "#f87171",
          "❌ Trouvé dans des fuites publiques !",
        );
      }
      if (isWeak) {
        weakCounter++;
        // Au premier élément trouvé, on nettoie le texte d'attente "Analyse de la force..."
        if (weakCounter === 1) reportListWeakEl.innerHTML = "";
        appendReportRow(
          reportListWeakEl,
          entry,
          "#fbbf24",
          `⚠️ ${weakReasons.join(" • ")}`,
        );
      }
    }

    // 4. Mise à jour des compteurs globaux
    weakCountEl.textContent = weakCounter;
    pwnedCountEl.textContent = pwnedCounter;

    // 5. Affichage des états de succès si les compteurs sont restés à 0
    if (pwnedCounter === 0) {
      reportListPwnedEl.innerHTML =
        "<p style='color: var(--color-success); font-size: 0.85rem; text-align: center; margin: 5px 0;'>✅ Aucun mot de passe compromis !</p>";
    }
    if (weakCounter === 0) {
      reportListWeakEl.innerHTML =
        "<p style='color: var(--color-success); font-size: 0.85rem; text-align: center; margin: 5px 0;'>✅ Tous vos mots de passe sont robustes !</p>";
    }
  });

  if (reportCloseBtn) {
    reportCloseBtn.addEventListener("click", () =>
      reportModal.classList.add("hidden"),
    );
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
const guideOkBtn = document.getElementById("guide-ok-btn");

if (guideBtn && guideModal) {
  guideBtn.addEventListener("click", () => {
    guideModal.classList.remove("hidden");
  });

  if (guideOkBtn) {
    guideOkBtn.addEventListener("click", () =>
      guideModal.classList.add("hidden"),
    );
  }

  // ❌ Écouteur sur la croix de fermeture
  const guideCloseCross = guideModal.querySelector(".modal-close");
  if (guideCloseCross) {
    guideCloseCross.addEventListener("click", () => {
      guideModal.classList.add("hidden");
    });
  }

  // Permet aussi de fermer en cliquant à côté de la modale guide
  guideModal.addEventListener("click", (e) => {
    if (e.target === guideModal) guideModal.classList.add("hidden");
  });

  // ==========================================================================
  // 📁 LOGIQUE DE LA MODALE DOSSIER PERSONNALISÉE
  // ==========================================================================
  const addFolderBtn = document.getElementById("add-folder-btn");
  const folderModal = document.getElementById("folder-modal");
  const folderModalClose = document.getElementById("folder-modal-close");
  const folderCancelBtn = document.getElementById("folder-cancel-btn");
  const folderConfirmBtn = document.getElementById("folder-confirm-btn");
  const newFolderNameInput = document.getElementById("new-folder-name");
  const folderError = document.getElementById("folder-error");

  // Ouvre la modale
  if (addFolderBtn && folderModal) {
    addFolderBtn.addEventListener("click", () => {
      newFolderNameInput.value = "";
      folderError.textContent = "";
      folderModal.classList.remove("hidden");
      newFolderNameInput.focus();
    });
  }

  // Ferme la modale
  const closeFolderModal = () => {
    folderModal.classList.add("hidden");
  };

  if (folderModalClose)
    folderModalClose.addEventListener("click", closeFolderModal);
  if (folderCancelBtn)
    folderCancelBtn.addEventListener("click", closeFolderModal);

  // Ferme si on clique à l'extérieur de la carte
  if (folderModal) {
    folderModal.addEventListener("click", (e) => {
      if (e.target === folderModal) closeFolderModal();
    });
  }

  // Soumission du dossier
  if (folderConfirmBtn) {
    folderConfirmBtn.addEventListener("click", async () => {
      folderError.textContent = "";
      const folderName = newFolderNameInput.value.trim();

      if (!folderName) {
        folderError.textContent = "Le nom du dossier ne peut pas être vide.";
        return;
      }

      // Vérification de doublon
      const folderExists = vaultEntries.some(
        (entry) =>
          entry.folder &&
          entry.folder.toLowerCase() === folderName.toLowerCase(),
      );

      if (folderExists) {
        folderError.textContent = "Ce dossier existe déjà !";
        return;
      }

      const emptyPayload = {
        url: "",
        username: "",
        password: "",
      };

      try {
        folderConfirmBtn.disabled = true;
        folderConfirmBtn.textContent = "Création...";

        const encryptedData = await encryptString(
          JSON.stringify(emptyPayload),
          vaultKey,
        );

        const res = await fetch(`${API_URL}/vault`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${userToken}`,
          },
          body: JSON.stringify({
            type: "login",
            label: `[Dossier Vide] ${folderName}`,
            encryptedData: encryptedData,
            folder: folderName,
          }),
        });

        if (res.ok) {
          await fetchVaultItems();
          renderEntries(searchInput.value);
          closeFolderModal();
          showToast(`📁 Dossier "${folderName}" créé avec succès !`);
        } else {
          folderError.textContent = "Échec de la sauvegarde sur le serveur.";
        }
      } catch (err) {
        console.error(err);
        folderError.textContent = "Erreur technique lors de l'enregistrement.";
      } finally {
        folderConfirmBtn.disabled = false;
        folderConfirmBtn.textContent = "Créer le dossier";
      }
    });

    // Permet de valider en appuyant sur la touche "Entrée" dans l'input
    newFolderNameInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        folderConfirmBtn.click();
      }
    });
  }
}
