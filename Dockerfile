FROM nginx:alpine

# Copie explicite du contenu public uniquement — évite d'exposer nginx/, .git,
# .github, README.md ou .htaccess (qui n'a aucun effet sur nginx, voir README) via
# le serveur statique.
COPY index.html activity.html forgot-password.html reset-password.html 404.html maintenance.html /usr/share/nginx/html/
COPY src/ /usr/share/nginx/html/src/
COPY assets/ /usr/share/nginx/html/assets/

# Deux configs au choix : service normal (URLs propres + page 404 personnalisée),
# ou mode maintenance (503 partout). Sélectionnées au démarrage du conteneur via
# la variable d'environnement MAINTENANCE_MODE (voir CMD).
COPY nginx/app.conf /etc/nginx/conf.d/app.conf.template
COPY nginx/maintenance.conf /etc/nginx/conf.d/maintenance.conf.template

CMD sh -c ' \
  if [ "$MAINTENANCE_MODE" = "true" ]; then \
    cp /etc/nginx/conf.d/maintenance.conf.template /etc/nginx/conf.d/default.conf; \
  else \
    cp /etc/nginx/conf.d/app.conf.template /etc/nginx/conf.d/default.conf; \
  fi && \
  sed -i -e "s/80/$PORT/g" /etc/nginx/conf.d/default.conf && \
  nginx -g "daemon off;"'
