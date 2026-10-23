# Alaga API for Cloud Run (built from this folder: api/Dockerfile).
FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY migrations ./migrations
USER node
CMD ["node", "src/server.js"]
