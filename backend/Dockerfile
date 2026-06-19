# Use an official Python runtime as a parent image
FROM python:3.12

RUN apt-get update && apt-get install -y docker.io

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
RUN pip install poetry

COPY pyproject.toml poetry.lock ./

#RUN poetry install --no-root
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root

COPY . /app

# Expose the port your application listens on (if applicable)
EXPOSE 8000

ENV PYTHONPATH="${PYTHONPATH}:/app/src"

# Copy a startup script
COPY bin/entry_point.sh ./
RUN chmod +x /app/entry_point.sh

COPY bin/analyze.py ./
RUN chmod +x /app/analyze.py

# Define the command to run your application
CMD ["/app/entry_point.sh"]
