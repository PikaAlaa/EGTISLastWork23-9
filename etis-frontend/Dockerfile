FROM node:24-slim AS build
WORKDIR /web
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build
FROM node:24-slim
WORKDIR /web
COPY --from=build /web/dist ./dist
COPY server.mjs ./
ENV ETIS_WEB_HOST=0.0.0.0
CMD ["node","server.mjs"]
