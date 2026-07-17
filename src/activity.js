const API_URL =
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1"
    ? "http://localhost:3000"
    : "https://api.swordmanager.cloud";

// Chaque action est rattachée à une catégorie utilisée pour le filtrage et le code couleur
const ACTIVITY_LABELS = {
  login: { text: "Connexion", category: "connexion" },
  logout: { text: "Déconnexion", category: "connexion" },
  logout_auto: {
    text: "Déconnexion automatique (inactivité)",
    category: "connexion",
  },
  item_created: { text: "Identifiant ajouté", category: "ajout" },
  folder_created: { text: "Dossier créé", category: "ajout" },
  item_updated: { text: "Identifiant modifié", category: "modification" },
  item_moved: { text: "Identifiant déplacé", category: "modification" },
  item_deleted: { text: "Identifiant supprimé", category: "suppression" },
  folder_deleted: { text: "Dossier supprimé", category: "suppression" },
  password_copied: { text: "Mot de passe copié", category: "consultation" },
  password_revealed: {
    text: "Mot de passe affiché",
    category: "consultation",
  },
};

const CATEGORIES = [
  { id: "all", label: "Tout" },
  { id: "connexion", label: "Connexions" },
  { id: "ajout", label: "Ajouts" },
  { id: "modification", label: "Modifications" },
  { id: "suppression", label: "Suppressions" },
  { id: "consultation", label: "Mots de passe consultés" },
];

redirectIfBackendDown(API_URL);

let allLogs = [];
let activeCategory = "all";

function showToast(message) {
  const toast = document.getElementById("toast");
  toast.innerText = message;
  toast.className = "toast-visible";
  setTimeout(() => {
    toast.className = "toast-hidden";
  }, 4000);
}

function getSessionToken() {
  const raw = sessionStorage.getItem("sword_session");
  if (!raw) return null;
  try {
    const session = JSON.parse(raw);
    if (session.expiresAt && Date.now() > session.expiresAt) return null;
    return session.token || null;
  } catch {
    return null;
  }
}

// Regroupe les entrées par jour calendaire ("Aujourd'hui", "Hier", ou date complète)
function dayLabelFor(date) {
  const now = new Date();
  const startOfToday = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate(),
  );
  const startOfEntryDay = new Date(
    date.getFullYear(),
    date.getMonth(),
    date.getDate(),
  );
  const diffDays = Math.round(
    (startOfToday - startOfEntryDay) / (1000 * 60 * 60 * 24),
  );

  if (diffDays === 0) return "Aujourd'hui";
  if (diffDays === 1) return "Hier";
  return startOfEntryDay.toLocaleDateString("fr-FR", {
    weekday: "long",
    day: "numeric",
    month: "long",
    year: "numeric",
  });
}

function renderFilters() {
  const container = document.getElementById("activity-filters");
  if (!container) return;
  container.innerHTML = "";

  CATEGORIES.forEach((category) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "filter-chip";
    chip.classList.toggle("active", activeCategory === category.id);
    chip.textContent = category.label;
    chip.addEventListener("click", () => {
      activeCategory = category.id;
      renderFilters();
      renderActivity();
    });
    container.appendChild(chip);
  });
}

function renderActivity() {
  const container = document.getElementById("activity-page-list");
  container.innerHTML = "";

  const logs =
    activeCategory === "all"
      ? allLogs
      : allLogs.filter(
          (log) =>
            (ACTIVITY_LABELS[log.action]?.category || "autre") ===
            activeCategory,
        );

  if (logs.length === 0) {
    const empty = document.createElement("p");
    empty.style.color = "var(--color-text-muted)";
    empty.textContent =
      allLogs.length === 0
        ? "Aucune activité enregistrée pour le moment."
        : "Aucune activité ne correspond à ce filtre.";
    container.appendChild(empty);
    return;
  }

  let currentDayLabel = null;
  let dayGroup = null;

  logs.forEach((log) => {
    const date = new Date(log.createdAt);
    const label = dayLabelFor(date);

    if (label !== currentDayLabel) {
      currentDayLabel = label;

      const dayHeader = document.createElement("h3");
      dayHeader.textContent = label;
      dayHeader.style.margin = "24px 0 8px 0";
      dayHeader.style.color = "var(--color-text-muted)";
      dayHeader.style.fontSize = "0.85rem";
      dayHeader.style.textTransform = "uppercase";
      dayHeader.style.letterSpacing = "0.05em";
      container.appendChild(dayHeader);

      dayGroup = document.createElement("div");
      dayGroup.className = "modal-card";
      dayGroup.style.maxWidth = "none";
      dayGroup.style.padding = "4px 16px";
      container.appendChild(dayGroup);
    }

    const meta = ACTIVITY_LABELS[log.action] || {
      text: log.action,
      category: "autre",
    };

    const row = document.createElement("div");
    row.className = `activity-row activity-row-${meta.category}`;

    const infoDiv = document.createElement("div");
    infoDiv.style.flex = "1";
    infoDiv.style.minWidth = "0";

    const strongAction = document.createElement("strong");
    strongAction.style.display = "block";
    strongAction.textContent = `${meta.text}${
      log.detail ? " — " + log.detail : ""
    }`;

    const spanTime = document.createElement("span");
    spanTime.style.color = "var(--color-text-muted)";
    spanTime.style.fontSize = "0.8rem";
    spanTime.textContent = date.toLocaleTimeString("fr-FR", {
      hour: "2-digit",
      minute: "2-digit",
    });

    infoDiv.appendChild(strongAction);
    infoDiv.appendChild(spanTime);

    const spanIp = document.createElement("span");
    spanIp.style.color = "var(--color-text-muted)";
    spanIp.style.fontSize = "0.8rem";
    spanIp.style.whiteSpace = "nowrap";
    spanIp.textContent = log.ip || "";

    row.appendChild(infoDiv);
    row.appendChild(spanIp);
    dayGroup.appendChild(row);
  });
}

// Verrouille la session (best-effort côté log) et renvoie vers le coffre, qui
// affichera directement le formulaire de connexion puisque la session est effacée.
function lockAndRedirectToLogin() {
  const token = getSessionToken();
  sessionStorage.removeItem("sword_session");
  stopSessionGuard();

  if (token) {
    fetch(`${API_URL}/activity`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ action: "logout_auto" }),
    }).catch(() => {});
  }

  window.location.href = "/";
}

async function loadActivity() {
  const token = getSessionToken();
  const container = document.getElementById("activity-page-list");

  if (!token) {
    container.innerHTML =
      "<p style='color: var(--color-text-muted);'>Session expirée. Veuillez vous reconnecter depuis le coffre pour consulter l'historique.</p>";
    return;
  }

  container.innerHTML =
    "<p style='color: var(--color-text-muted);'>Chargement de l'historique...</p>";

  try {
    const res = await fetch(`${API_URL}/activity`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error("Failed to load activity log.");

    allLogs = await res.json();
    renderFilters();
    renderActivity();
    startSessionGuard(() => !!getSessionToken(), lockAndRedirectToLogin);
  } catch (err) {
    console.error(err);
    container.innerHTML =
      "<p style='color: var(--color-danger);'>Impossible de charger l'historique.</p>";
    showToast("Le serveur est injoignable.");
  }
}

loadActivity();
