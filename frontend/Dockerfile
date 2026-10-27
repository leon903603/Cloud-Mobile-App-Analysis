# frontend/Dockerfile — multi-stage: build static assets, serve via nginx

# --- Build stage ---
FROM node:22.23.4-alpine AS build

WORKDIR /app

COPY package*.json ./
# npm ci: deterministic from the lockfile, and skips dependency resolution.
RUN npm ci

COPY . .
RUN npm run build

# --- Serve stage ---
FROM nginx:alpine

# Built SPA
COPY --from=build /app/dist /usr/share/nginx/html
# Reverse-proxy + TLS config
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80 443
