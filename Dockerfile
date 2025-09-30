# Dockerfile
FROM node:18-alpine

WORKDIR /usr/src/app

# install dependencies (expects package-lock.json)
COPY package*.json ./
RUN npm ci --production

# copy app files
COPY . .

# ensure uploads dir exists
RUN mkdir -p /usr/src/app/uploads && chown -R node:node /usr/src/app/uploads

# use non-root user
USER node

EXPOSE 3000
CMD ["node", "server.js"]
