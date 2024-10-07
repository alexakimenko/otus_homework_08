import logging
from abc import ABC, abstractmethod

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Store(ABC):
    """Abstract base class for key-value stores."""

    @abstractmethod
    def get(self, key):
        """Retrieve value by key from the store. Raises exception if fails."""
        pass

    @abstractmethod
    def cache_get(self, key):
        """Retrieve value by key from the cache. Returns None if fails."""
        pass

