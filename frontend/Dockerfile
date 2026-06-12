FROM node:20-alpine AS base
WORKDIR /app

# Install dependencies first (cached layer)
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install

# Copy source (node_modules excluded via .dockerignore at repo root)
COPY frontend/ ./

# Ensure all bin stubs are executable — guards against Windows host builds
# where NTFS permissions don't carry +x to the Linux container.
RUN chmod -R +x node_modules/.bin/

EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]
