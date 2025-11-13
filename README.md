# PII Removal Tool

A production-ready web application for detecting and removing Personally Identifiable Information (PII) from text, with special support for Australian data formats.

## Features

- **Three Processing Modes:**
  - **Anonymize**: Replace PII with generic placeholders (e.g., `<PERSON>`, `<PHONE_NUMBER>`)
  - **De-identify**: Replace PII with numbered placeholders (e.g., `PERSON_001`) - fully reversible
  - **Re-identify**: Restore original values from de-identified text

- **Australian-Specific PII Detection:**
  - Tax File Number (TFN)
  - Australian Business Number (ABN)
  - Australian Company Number (ACN)
  - Medicare Number
  - Australian phone numbers

- **Global PII Detection:**
  - Personal names
  - Email addresses
  - Phone numbers
  - Locations/addresses
  - Credit card numbers
  - IBAN codes
  - And more...

- **Advanced Features:**
  - Configurable entity type selection
  - Adjustable confidence threshold
  - LastName, FirstName pattern detection
  - Custom names dictionary support
  - Ignore list for false positives
  - Local processing (no cloud services)
  - Beautiful, responsive web UI

## Quick Start with Docker

The fastest way to deploy is using Docker:

```bash
# Build and run with docker-compose
docker-compose up -d

# Access the application
open http://localhost:5000
```

## Manual Installation

### Prerequisites

- Python 3.11+
- pip

### Installation Steps

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd pii_removal_tool
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Download spaCy language model:**
   ```bash
   python -m spacy download en_core_web_lg
   ```

5. **Configure environment (optional):**
   ```bash
   cp .env.example .env
   # Edit .env with your preferred settings
   ```

6. **Run the application:**

   **Development mode:**
   ```bash
   python app.py
   ```

   **Production mode (with Gunicorn):**
   ```bash
   gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 wsgi:app
   ```

7. **Access the application:**
   Open your browser to `http://localhost:5000`

## Configuration

### Environment Variables

Create a `.env` file (use `.env.example` as template):

```bash
# Flask Configuration
DEBUG=False
SECRET_KEY=your-secret-key-here-change-in-production
PORT=5000

# Data Directory
DATA_DIR=./data

# Logging
LOG_LEVEL=INFO
```

### Optional Configuration Files

Place these JSON files in the `data/` directory:

1. **`custom_names.json`** - Additional names to detect as PII:
   ```json
   [
     "John Smith",
     "Jane Doe",
     "Acme Corporation"
   ]
   ```

2. **`ignore_list.json`** - Words to ignore during detection:
   ```json
   [
     "Australia",
     "Melbourne",
     "Admin"
   ]
   ```

3. **`pii_mappings.json`** - Auto-generated mapping file for de-identification (don't edit manually)

## Deployment Options

### Option 1: Docker (Recommended)

**Build the image:**
```bash
docker build -t pii-removal-tool .
```

**Run the container:**
```bash
docker run -d \
  -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  --name pii-removal-tool \
  pii-removal-tool
```

**Or use docker-compose:**
```bash
docker-compose up -d
```

### Option 2: Cloud Platforms

#### Heroku

1. Install Heroku CLI
2. Create a `Procfile`:
   ```
   web: gunicorn --bind 0.0.0.0:$PORT --workers 4 --timeout 120 wsgi:app
   ```
3. Deploy:
   ```bash
   heroku create your-app-name
   git push heroku main
   ```

#### AWS EC2

1. Launch an EC2 instance (Ubuntu 22.04 recommended)
2. SSH into the instance
3. Install dependencies:
   ```bash
   sudo apt update
   sudo apt install python3.11 python3.11-venv python3-pip nginx
   ```
4. Clone and setup the application
5. Configure nginx as reverse proxy
6. Use systemd to run as a service

#### Google Cloud Run

1. Build and push Docker image to GCR:
   ```bash
   gcloud builds submit --tag gcr.io/PROJECT_ID/pii-removal-tool
   ```
2. Deploy to Cloud Run:
   ```bash
   gcloud run deploy pii-removal-tool \
     --image gcr.io/PROJECT_ID/pii-removal-tool \
     --platform managed \
     --region us-central1 \
     --allow-unauthenticated
   ```

#### Azure Web App

1. Create a Web App in Azure Portal
2. Configure deployment from GitHub or push Docker image to Azure Container Registry
3. Set environment variables in Application Settings

### Option 3: Traditional Server

1. Install on server (Ubuntu example):
   ```bash
   # Install Python and dependencies
   sudo apt update
   sudo apt install python3.11 python3.11-venv python3-pip nginx supervisor

   # Clone repository
   cd /opt
   sudo git clone <repository-url> pii-removal-tool
   cd pii-removal-tool

   # Setup virtual environment
   python3.11 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python -m spacy download en_core_web_lg
   ```

2. Create systemd service (`/etc/systemd/system/pii-removal.service`):
   ```ini
   [Unit]
   Description=PII Removal Tool
   After=network.target

   [Service]
   User=www-data
   Group=www-data
   WorkingDirectory=/opt/pii-removal-tool
   Environment="PATH=/opt/pii-removal-tool/venv/bin"
   ExecStart=/opt/pii-removal-tool/venv/bin/gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 wsgi:app

   [Install]
   WantedBy=multi-user.target
   ```

3. Configure nginx as reverse proxy (`/etc/nginx/sites-available/pii-removal`):
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;

       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

4. Enable and start:
   ```bash
   sudo systemctl enable pii-removal
   sudo systemctl start pii-removal
   sudo ln -s /etc/nginx/sites-available/pii-removal /etc/nginx/sites-enabled/
   sudo systemctl restart nginx
   ```

## API Usage

### Process Text

**Endpoint:** `POST /process`

**Request body:**
```json
{
  "text": "John Smith lives in Sydney. His email is john@example.com",
  "action": "anonymize",
  "threshold": 0.5,
  "enabled_entities": ["PERSON", "EMAIL_ADDRESS", "LOCATION"]
}
```

**Response:**
```json
{
  "result": "<PERSON> lives in <LOCATION>. His email is <EMAIL_ADDRESS>",
  "entities_found": 3
}
```

### Health Check

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "healthy",
  "service": "pii-removal-tool",
  "version": "1.0.0"
}
```

### Clear Mappings

**Endpoint:** `POST /clear_mappings`

**Response:**
```json
{
  "message": "Mappings cleared successfully"
}
```

## Project Structure

```
pii_removal_tool/
├── app.py                 # Main application
├── config.py              # Configuration management
├── wsgi.py               # WSGI entry point
├── requirements.txt      # Python dependencies
├── Dockerfile           # Docker configuration
├── docker-compose.yml   # Docker Compose configuration
├── .env.example         # Environment variables template
├── .gitignore          # Git ignore rules
├── README.md           # This file
└── data/               # Data directory (JSON files)
    ├── .gitkeep
    ├── pii_mappings.json      # Auto-generated
    ├── custom_names.json      # Optional
    └── ignore_list.json       # Optional
```

## Security Considerations

- **Change the SECRET_KEY**: Always set a strong, random secret key in production
- **Use HTTPS**: Deploy behind a reverse proxy with SSL/TLS
- **Data Privacy**: All processing happens locally - no data sent to external services
- **File Permissions**: Ensure proper permissions on data directory
- **Regular Updates**: Keep dependencies updated for security patches
- **Rate Limiting**: Consider adding rate limiting for public deployments

## Performance Tuning

### Gunicorn Workers

Adjust the number of workers based on your server:
```bash
# Formula: (2 × CPU cores) + 1
gunicorn --workers 4 --timeout 120 wsgi:app
```

### Memory Requirements

- Minimum: 2GB RAM
- Recommended: 4GB+ RAM
- spaCy model requires ~500MB

### Caching

For high-traffic deployments, consider:
- Redis for session management
- CDN for static assets
- Application-level caching for common queries

## Troubleshooting

### spaCy Model Not Found

```bash
python -m spacy download en_core_web_lg
```

### Port Already in Use

```bash
# Linux/Mac
lsof -ti:5000 | xargs kill -9

# Change port in .env
PORT=8000
```

### Permission Denied on data/

```bash
sudo chown -R $USER:$USER data/
chmod 755 data/
```

### Docker Build Fails

```bash
# Clear Docker cache
docker system prune -a
docker-compose build --no-cache
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Your License Here]

## Acknowledgments

- Built with [Microsoft Presidio](https://microsoft.github.io/presidio/)
- Uses [spaCy](https://spacy.io/) for NLP
- Australian recognizers from Presidio predefined recognizers

## Support

For issues and questions:
- Open an issue on GitHub
- Check existing documentation
- Review troubleshooting section

---

**Note:** This tool processes sensitive data. Always review your security requirements and compliance obligations before deploying in production.
