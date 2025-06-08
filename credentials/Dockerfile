# Use Python 3.13.3 as the base image
FROM python:3.13.3-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the required Python packages
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Expose the port the app runs on
EXPOSE 5002

# Run the application
CMD ["fastapi", "run", "main.py", "--port", "5002"]