FROM python:3.12
WORKDIR /app
# Install dependencies
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install uvicorn

# Copy entire project (including the 'app' package directory)
COPY . .

EXPOSE 8000
# Start the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
