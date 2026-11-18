
# File Integrity Monitoring and Tamper Detection System

A Python-based cybersecurity project that monitors files and folders to detect unauthorized changes. It uses SHA-256 hashing to maintain a baseline of trusted files and identify modifications, deletions, new files, and renamed files.

## Features

- SHA-256 based file integrity checking
- Detection of file creation, modification, deletion, and renaming
- Real-time monitoring using Watchdog
- Periodic file scanning
- SQLite database for storing file details and security events
- Password-protected baseline updates
- HMAC-based baseline tamper detection
- Streamlit dashboard for viewing alerts and file status
- Activity logs and security report generation

## Technologies Used

- Python
- Streamlit
- SQLite
- SHA-256
- HMAC
- Watchdog

## Project Structure

```text
fim_project/
├── dashboard.py
├── cli.py
├── demo_scenarios.py
├── requirements.txt
├── fim/
├── sample_files/
├── tests/
├── screenshots/
└── docs/
```

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd fim_project
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the environment:

**Windows:**
```powershell
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run the Project

Start the dashboard:

```bash
streamlit run dashboard.py
```

Open the local URL displayed in the terminal.

## Run Tests

```bash
python -m unittest discover -s tests -t . -v
```

Run demonstration scenarios:

```bash
python demo_scenarios.py
```

## How It Works

1. Select a folder to monitor.
2. Generate SHA-256 hashes for existing files.
3. Store the hashes as a trusted baseline.
4. Monitor files for changes using Watchdog and periodic scans.
5. Compare current hashes with the stored baseline.
6. Generate alerts when unauthorized changes are detected.
7. Approve legitimate changes using the admin password.

## Security Note

This project is developed for educational purposes. Monitor only files and folders that you own or have permission to access. The system detects unauthorized changes but does not prevent them.
