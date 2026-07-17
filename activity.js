const API_URL =
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1"
    ? "http://localhost:3000"
    : "https://api.swordmanager.cloud";

const ACTIVITY_LABELS = {
  login: { icon: "🔑", text: "Connexion" },
  logout: { icon: "🚪", text: "Déconnexion" },
  logout_auto: { icon: "⏳", text: "Déconnexion automatique (inactivité)" },
  item_created: { icon: "➕", text: "Identifiant ajouté" },
  item_updated: { icon: "✏️", text: "Identifiant modifié" },
  item_deleted: { icon: "🗑️", text: "Identifiant supprimé" },
  password_copied: { icon: "📋", text: "Mot de passe copié" },
  password_revealed: { icon: "👁️", text: "Mot de passe affiché" },
};

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

function renderActivity(logs) {
  const container = document.getElementById("activity-page-list");
  container.innerHTML = "";

  if (logs.length === 0) {
    const empty = document.createElement("p");
    empty.style.color = "var(--color-text-muted)";
    empty.textContent = "Aucune activité enregistrée pour le moment.";
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
      icon: "•",
      text: log.action,
    };

    const row = document.createElement("div");
    row.style.borderBottom = "1px solid var(--color-border)";
    row.style.padding = "12px 0";
    row.style.display = "flex";
    row.style.justifyContent = "space-between";
    row.style.alignItems = "center";
    row.style.gap = "10px";

    const infoDiv = document.createElement("div");
    infoDiv.style.flex = "1";
    infoDiv.style.minWidth = "0";

    const strongAction = document.createElement("strong");
    strongAction.style.display = "block";
    strongAction.textContent = `${meta.icon} ${meta.text}${
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

    const logs = await res.json();
    renderActivity(logs);
  } catch (err) {
    console.error(err);
    container.innerHTML =
      "<p style='color: var(--color-danger);'>Impossible de charger l'historique.</p>";
    showToast("☁️ Le serveur est injoignable.");
  }
}

loadActivity();
