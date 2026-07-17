// Vérifie que l'API est joignable avant de rendre une page authentifiée. Ne
// distingue volontairement que l'injoignabilité totale (réseau coupé, backend
// arrêté, DNS/CORS cassé) d'une réponse HTTP normale — une erreur 4xx/5xx sur un
// appel métier ponctuel reste gérée localement par chaque page (toast), ce
// contrôle ne sert qu'à éviter d'afficher un formulaire de connexion ou un coffre
// cassé quand le backend entier est down.
const BACKEND_STATUS_TIMEOUT_MS = 4000;

async function redirectIfBackendDown(apiUrl) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), BACKEND_STATUS_TIMEOUT_MS);

  try {
    await fetch(`${apiUrl}/health`, { signal: controller.signal });
    return false;
  } catch (err) {
    window.location.href = "/maintenance.html";
    return true;
  } finally {
    clearTimeout(timeout);
  }
}
