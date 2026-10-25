# Alaga API for Cloud Run. Works whether the build starts in the repo root
# (Cloud Run's "Dockerfile: /api/Dockerfile") or in the api/ folder.
FROM node:20-slim AS src
COPY . /ctx
RUN mkdir /app && if [ -f /ctx/api/package.json ]; then cp -r /ctx/api/. /app/; else cp -r /ctx/. /app/; fi \
 && rm -rf /app/node_modules /app/test

FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=src /app/package.json /app/package-lock.json ./
RUN npm ci --omit=dev
COPY --from=src /app/src ./src
COPY --from=src /app/migrations ./migrations
USER node
CMD ["node", "src/server.js"]
