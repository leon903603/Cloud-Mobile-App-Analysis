# server/Dockerfile
# glibc (not alpine/musl) on purpose: better-sqlite3 publishes prebuilt binaries for
# glibc only, so alpine forces a node-gyp source build of SQLite (~250k lines of C).
# That took many minutes on the EC2 box; on bookworm the prebuild just downloads.
FROM node:22-bookworm-slim

WORKDIR /usr/src/app

COPY package*.json ./
# npm ci: deterministic from the lockfile; fallback to npm install if lockfile is slightly out of sync
RUN npm ci || npm install

COPY . .

EXPOSE 3000

CMD ["npx", "tsx", "index.ts"]
