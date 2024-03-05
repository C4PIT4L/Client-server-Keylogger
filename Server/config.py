import logging
import re
import os

# Server configurations
SERVER_IP = "10.100.102.18"
SERVER_PORT = 8042
KEY_FILE = None
CERT_FILE = None

# Logging configurations
LOG_FILENAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Logs', 'server_logs.log')
LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(asctime)s %(message)s'
LOG_DATE_FORMAT = '%d/%m/%Y %I:%M:%S %p'

# Rate limiting configurations
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 1000
MAX_THREADS = 100

# Other configurations
FAILED_LOGIN_ATTEMPTS = 30
BLOCKED_IP_DURATION = 60
SPOOFED_IPS = ["192.168.1.2", "192.168.1.3"]

# Patterns for detecting suspicious content
PATTERNS = {
            "SQL Injection": [r"(?i)('.+--|\b(ALTER|CREATE|DELETE|DROP|RENAME|INSERT|SELECT|UPDATE|UNION|WHERE)\b)",
                              re.I],
            "Cross-Site Scripting": [r"(?i)(<\b(script|img|div|table|iframe)\b.*?>)", re.I],
            "XPath Injection": [r"(?i)('|\)|\(|=|' or ')", re.I],
            "Buffer Overflow": [r"(?i)(%s|%d|%n|%x|%o|%p|%u|%ld|%lu|%lx|%lo|%hu|%hx|%ho|%Lf|%Lf|%Lf|%Lf|%Lf|%Lf)",
                                re.I],
            "Format String Attack": [
                r"(?i)(%[^ ]*[sdioxXufFeEgGaAcsCSpnm]|%\.{0,}[0-9]{0,}[^ ]*[sdioxXufFeEgGaAcsCSpnm])", re.I],
            "CRLF Injection": [r"(%0D|%0A|%0D%0A|%0d|%0a|%0d%0a|\r|\n|\r\n)", re.I]
        }
# Patterns for errors
ERRORS = {
    "INVALID_COMMAND": "Invalid command",
    "DATABASE_ERROR": "Database error occurred",
    "SSL_ERROR": "SSL error occurred",
    "CERTIFICATE_ERROR": "Certificate error occurred",
    "CONNECTION_RESET": "Client connection reset",
    "CONNECTION_ABORTED": "Client connection aborted",
    "MAX_THREADS_REACHED": "Maximum number of active threads reached",
    "RATE_LIMIT_EXCEEDED": "Client exceeded rate limit",
    "USER_ALREADY_LOGGED_IN": "User is already logged in",
    "USER_NOT_FOUND": "User not found",
    "LOGIN_BLOCKED_IP": "Your IP is temporarily blocked due to too many failed login attempts",
    "SOCKET_ERROR": "Socket error occurred",
    "EXCEPTION": "An exception occurred",
}


# Database file path
DATABASE_FILE = 'users_new.db'
