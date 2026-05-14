FROM node:20-alpine AS base
WORKDIR /app

COPY frontend/package.json ./
RUN npm install

COPY frontend/ ./

EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]
