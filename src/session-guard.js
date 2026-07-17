// Verrouillage automatique par inactivité (5 min), partagé entre toutes les pages
// (index.html, activity.html) pour garantir le même comportement de sécurité partout.
// Basé sur une horloge murale (Date.now()) vérifiée périodiquement plutôt que sur un
// setTimeout unique : un setTimeout long peut être fortement retardé par le navigateur
// quand l'onglet est en arrière-plan. Le contrôle sur "visibilitychange" rattrape
// immédiatement la vérification dès que l'onglet redevient actif.
const SESSION_GUARD_LIMIT_MS = 5 * 60 * 1000;

let sessionGuardLastActivityAt = null;
let sessionGuardInterval = null;
let sessionGuardIsActive = null;
let sessionGuardOnInactive = null;

function sessionGuardMarkActivity(e) {
  sessionGuardLastActivityAt = Date.now();
  // Diagnostic optionnel : dans la console, exécuter `SESSION_GUARD_DEBUG = true`
  // avant de laisser la page inactive pour voir en direct ce qui relance le minuteur.
  if (window.SESSION_GUARD_DEBUG) {
    console.debug(
      `[session-guard] activité détectée (${e?.type || "inconnu"})`,
      e?.target,
    );
  }
}

function sessionGuardCheck() {
  if (!sessionGuardIsActive || !sessionGuardIsActive() || !sessionGuardLastActivityAt) {
    return;
  }
  const elapsedMs = Date.now() - sessionGuardLastActivityAt;
  if (window.SESSION_GUARD_DEBUG) {
    console.debug(
      `[session-guard] vérification : ${Math.round(elapsedMs / 1000)}s d'inactivité (limite ${SESSION_GUARD_LIMIT_MS / 1000}s)`,
    );
  }
  if (elapsedMs >= SESSION_GUARD_LIMIT_MS) {
    sessionGuardOnInactive();
  }
}

function sessionGuardHandleVisibility() {
  if (document.visibilityState === "visible") sessionGuardCheck();
}

// isActive: () => bool — indique si une session doit actuellement être surveillée
// onInactive: () => void — appelé quand l'inactivité dépasse la limite
function startSessionGuard(isActive, onInactive) {
  sessionGuardIsActive = isActive;
  sessionGuardOnInactive = onInactive;
  sessionGuardLastActivityAt = Date.now();

  window.addEventListener("mousemove", sessionGuardMarkActivity);
  window.addEventListener("keydown", sessionGuardMarkActivity);
  window.addEventListener("click", sessionGuardMarkActivity);
  window.addEventListener("scroll", sessionGuardMarkActivity, true);
  document.addEventListener("visibilitychange", sessionGuardHandleVisibility);
  sessionGuardInterval = setInterval(sessionGuardCheck, 15000);
}

function stopSessionGuard() {
  window.removeEventListener("mousemove", sessionGuardMarkActivity);
  window.removeEventListener("keydown", sessionGuardMarkActivity);
  window.removeEventListener("click", sessionGuardMarkActivity);
  window.removeEventListener("scroll", sessionGuardMarkActivity, true);
  document.removeEventListener("visibilitychange", sessionGuardHandleVisibility);
  clearInterval(sessionGuardInterval);
  sessionGuardInterval = null;
  sessionGuardLastActivityAt = null;
}
