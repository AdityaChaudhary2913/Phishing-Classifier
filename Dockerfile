# Base Image
FROM python:3.8-slim-buster

RUN apt-get update && apt-get install -y \
    libhdf5-dev \
    build-essential \
    python3-dev \
    pkg-config \     
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Set environment variables
ENV MONGODB_URL="mongodb+srv://aditya1306:aditya1306@phishingclassifier.y2fj1x3.mongodb.net/?retryWrites=true&w=majority&appName=PhishingClassifier"
ENV AdminID="Aditya"
ENV AdminPassword="Train"
ENV SessionSecretKey="Token"

# Run app.py when the container launches
CMD ["python3", "app.py"]