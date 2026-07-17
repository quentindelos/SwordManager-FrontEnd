# 🗡️ SwordManager — Frontend

Interface web du gestionnaire de mots de passe **zero-knowledge** SwordManager. Vanilla JS, sans framework ni étape de build : ce qui est livré au navigateur est exactement le code source, un choix délibéré pour un outil de sécurité (auditabilité — pas de bundler/transpilation entre le code et ce qui s'exécute réellement).

Dépôt du backend associé : [SwordManager-BackEnd](../SwordManager-BackEnd).

## Sommaire

- [Stack technique](#-stack-technique)
- [Architecture zero-knowledge](#-architecture-zero-knowledge-côté-client)
- [Structure du projet](#-structure-du-projet)
- [Lancement en local](#-lancement-en-local)
- [Pages](#-pages)
- [Modules JS](#-modules-js)
- [Déploiement](#-déploiement)

## 🛠️ Stack technique

Aucune dépendance de build : HTML/CSS/JS natifs, chargés via des balises `<script>` classiques (pas de module system, fonctions globales partagées entre fichiers — voir [Modules JS](#-modules-js)). Le chiffrement s'appuie exclusivement sur la **Web Crypto API** native du navigateur.

## 🔐 Architecture zero-knowledge côté client

À l'inscription/connexion, le mot de passe maître ne quitte jamais l'appareil :

1. **Dérivation** (`deriveKeys`, `src/crypto.js`) : PBKDF2, 600 000 itérations, sel = email → une `encryptionKey` (AES-GCM) qui chiffre/déchiffre le coffre localement, et un `authHash` (SHA-256 de la clé dérivée) envoyé au serveur en guise de mot de passe.
2. **Clé de coffre** : une `rawVaultKey` aléatoire (32 octets) est générée à l'inscription ; chiffrée sous `encryptionKey` → `protectedKey`, envoyée au serveur.
3. **Clé de récupération** : une seconde clé aléatoire, affichée une seule fois à l'utilisateur (copiable/téléchargeable), chiffre elle aussi la `rawVaultKey` → `recoveryProtectedKey`. Elle ne quitte jamais le navigateur et permet de réinitialiser le mot de passe maître sans perdre le coffre.
4. **Session** : après connexion, `{token, keyB64, expiresAt}` est stocké dans `sessionStorage` (`sword_session`) pour survivre à un rechargement de page sans nouvelle saisie du mot de passe.
5. **Verrouillage automatique** : un minuteur basé sur l'horloge murale (pas un `setTimeout` unique, throttlé par les navigateurs en arrière-plan) déconnecte la session après 5 minutes d'inactivité (`src/session-guard.js`).

## 📂 Structure du projet

```
├── index.html               # Coffre : connexion/inscription, liste des identifiants, rapport de sécurité
├── activity.html            # Historique d'activité du compte (page dédiée, groupée par jour)
├── forgot-password.html     # Demande de réinitialisation de mot de passe
├── reset-password.html      # Finalisation de la réinitialisation (via clé de récupération)
├── src/
│   ├── crypto.js             # Primitives de chiffrement pures (dérivation, encrypt/decrypt, base64)
│   ├── session-guard.js      # Minuteur d'inactivité partagé entre les pages authentifiées
│   ├── app.js                 # Logique du coffre : auth, CRUD des items, dossiers, rapport de sécurité
│   ├── activity.js            # Chargement/filtrage/rendu du journal d'activité
│   ├── forgot-password.js     # Formulaire de demande de reset
│   ├── reset-password.js      # Déchiffrement de la clé de récupération + reset
│   └── style.css               # Feuille de style unique, responsive (mobile/tablette/desktop)
├── assets/
│   └── favicon.svg
├── Dockerfile                # Image nginx statique
└── .github/workflows/deploy.yml
```

## 🚀 Lancement en local

Ce projet est un ensemble de fichiers statiques : n'importe quel serveur HTTP statique convient, par exemple :

```bash
python3 -m http.server 5500
```

Le [backend](../SwordManager-BackEnd) doit tourner en parallèle sur `localhost:3000` (voir son README). L'URL de l'API est sélectionnée automatiquement selon l'hôte (`src/app.js`, `src/activity.js`, etc.) :

```js
window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
  ? "http://localhost:3000"
  : "https://api.swordmanager.cloud";
```

Aucune variable d'environnement n'est nécessaire côté frontend.

## 📄 Pages

| Page | Rôle |
|---|---|
| `index.html` | Connexion/inscription, coffre (liste, ajout, modification, suppression, dossiers), rapport de sécurité, menu (historique, clé de récupération, export, bonnes pratiques) |
| `activity.html` | Historique complet des actions du compte, groupé par jour, avec filtres par catégorie (connexions, ajouts, modifications, suppressions, consultations) |
| `forgot-password.html` | Saisie de l'email pour recevoir un lien de réinitialisation (réponse toujours générique, anti-énumération) |
| `reset-password.html` | Saisie de la clé de récupération sauvegardée + nouveau mot de passe ; déchiffre localement `recoveryProtectedKey` puis re-chiffre la clé du coffre |

## 🧩 Modules JS

Pas de bundler ni de module ES : chaque fichier expose des fonctions globales, chargées dans un ordre précis via des balises `<script>` successives.

- **`crypto.js`** : fonctions pures sans dépendance au DOM (`deriveKeys`, `encryptString`, `decryptString`, conversions base64/ArrayBuffer). Chargé avant tout script qui en dépend (`app.js`, `reset-password.js`).
- **`session-guard.js`** : `startSessionGuard(isActive, onInactive)` / `stopSessionGuard()`, partagé par `index.html` et `activity.html` pour un comportement d'inactivité identique sur toutes les pages authentifiées. Mode debug optionnel via `window.SESSION_GUARD_DEBUG = true` (log en console des événements d'activité détectés).
- **`app.js`** : point d'entrée du coffre — écran de démarrage anti-flash (FOUC), restauration de session, CRUD du coffre, dossiers, modale de clé de récupération, rapport de sécurité (score global + graphique en anneau CSS).
- **`activity.js`** : chargement de `GET /activity`, regroupement par jour (Aujourd'hui/Hier/date complète), filtres par catégorie.

## 🚢 Déploiement

Déploiement continu vers **Google Cloud Run** via GitHub Actions ([.github/workflows/deploy.yml](.github/workflows/deploy.yml)), déclenché sur push vers `main`. Le workflow construit l'image Docker (`Dockerfile`, nginx alpine servant les fichiers statiques tels quels), la pousse vers Artifact Registry, puis déploie sur Cloud Run.
