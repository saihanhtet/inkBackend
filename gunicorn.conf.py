# Gunicorn configuration file

# Define the host and port to bind to
bind = '0.0.0.0:8000'

# Number of worker processes (adjust based on your server's resources)
workers = 8

# Worker class for handling requests
worker_class = 'uvicorn.workers.UvicornWorker'

# Maximum number of requests a worker will process before restarting
max_requests = 1000

# Timeout for worker processes
timeout = 30

# Log level
loglevel = 'info'

accesslog = '-'

errorlog = '-'
