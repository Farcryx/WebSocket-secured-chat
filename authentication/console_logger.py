import logging
from rich.logging import RichHandler
from rich.console import Console

# Create a rich console
console = Console()

# Set up logging with rich
logging.basicConfig(
    level=logging.DEBUG,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)

# Create a logger
logger = logging.getLogger("server_logger")