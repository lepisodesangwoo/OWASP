FROM node:20-alpine

WORKDIR /app

# Install packages
COPY package.json ./
RUN npm install

# Copy application
COPY . .

# Create necessary directories
RUN mkdir -p uploads public views downloads

# Expose port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
