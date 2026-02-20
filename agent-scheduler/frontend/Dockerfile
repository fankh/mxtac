FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY . .

ARG API_HOST=localhost
ENV API_HOST=${API_HOST}
RUN npm run build

EXPOSE 13001

CMD ["npx", "next", "start", "--port", "13001"]
