# Pinned exact tag + SHA-256 manifest digest placeholder (replace TO_VERIFY_node via `docker buildx imagetools inspect` before step 5; docs/design/docker-lan-v1.md §10 D1)
FROM node:22.12.0-bookworm-slim@sha256:TO_VERIFY_node AS build
WORKDIR /web
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22.12.0-bookworm-slim@sha256:TO_VERIFY_node
WORKDIR /web
COPY --from=build /web/dist ./dist
COPY server.mjs proxy-routes.mjs ./
ENV ETIS_WEB_HOST=0.0.0.0
USER 1000:1000
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:5173/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node","server.mjs"]
