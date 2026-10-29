FROM node:22.13.1-alpine AS build
WORKDIR /workspace/frontend
ARG VITE_USE_FIXTURES=false
ARG VITE_API_URL=http://localhost:8000/api/v1
ENV VITE_USE_FIXTURES=$VITE_USE_FIXTURES VITE_API_URL=$VITE_API_URL
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
COPY fixtures/analysis-full.json /workspace/fixtures/analysis-full.json
COPY fixtures/analysis-partial.json /workspace/fixtures/analysis-partial.json
RUN npm run build

FROM nginx:1.27.4-alpine
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /workspace/frontend/dist /usr/share/nginx/html
EXPOSE 80
