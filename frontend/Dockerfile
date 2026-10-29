FROM node:22.13.1-alpine AS build
WORKDIR /workspace/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
COPY fixtures/analysis-full.json /workspace/fixtures/analysis-full.json
COPY fixtures/analysis-partial.json /workspace/fixtures/analysis-partial.json
RUN npm run build

FROM nginx:1.27.4-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /frontend/dist /usr/share/nginx/html
EXPOSE 80
