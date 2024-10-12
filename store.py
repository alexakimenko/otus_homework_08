import logging
from abc import ABC, abstractmethod
import time
import redis
from redis.exceptions import ConnectionError, TimeoutError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BaseStore(ABC):
    """Абстрактный базовый класс для всех хранилищ."""

    @abstractmethod
    def get(self, key: str):
        """Получить значение по ключу из персистентного хранилища."""
        pass

    @abstractmethod
    def cache_get(self, key: str):
        """Получить значение по ключу из кеша."""
        pass

    @abstractmethod
    def cache_set(self, key: str, value, expire: int):
        """Сохранить значение в кеше."""
        pass


class RedisStore(BaseStore):
    def __init__(self, host='localhost', port=6379, db=0, reconnect_attempts=5, timeout=2):
        self.host = host
        self.port = port
        self.db = db
        self.reconnect_attempts = reconnect_attempts
        self.timeout = timeout
        self.client = None
        self._connect()

    def _connect(self):
        """Пытается подключиться к Redis с заданным числом попыток."""
        attempt = 0
        while attempt < self.reconnect_attempts:
            try:
                self.client = redis.StrictRedis(
                    host=self.host,
                    port=self.port,
                    db=self.db,
                    socket_timeout=self.timeout,
                    socket_connect_timeout=self.timeout,
                    decode_responses=True  # Автоматически декодировать байты в строки
                )
                # Проверка соединения
                if self.client.ping():
                    logger.info("Успешно подключились к Redis")
                    return
            except (ConnectionError, TimeoutError) as e:
                attempt += 1
                logger.warning(f"Попытка подключения {attempt} к Redis не удалась: {e}")
                time.sleep(1)  # Ожидание перед следующей попыткой
        raise ConnectionError(f"Не удалось подключиться к Redis после {self.reconnect_attempts} попыток")

    def get(self, key: str):
        """Получает значение по ключу из персистентного хранилища."""
        try:
            value = self.client.get(key)
            return value
        except (ConnectionError, TimeoutError) as e:
            logger.error(f"Ошибка при получении ключа '{key}': {e}")
            raise

    def cache_get(self, key: str):
        """Получает значение по ключу из кеша. Возвращает None в случае неудачи."""
        try:
            value = self.client.get(key)
            return value
        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"Ошибка при получении кеша для ключа '{key}': {e}")
            return None

    def cache_set(self, key: str, value, expire: int):
        """Сохраняет значение в кеше."""
        try:
            self.client.setex(key, expire, value)
        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"Ошибка при сохранении кеша для ключа '{key}': {e}")
            return None


class Store:
    """Фасадный класс для работы с различными реализациями хранилищ."""

    def __init__(self, backend: str = 'redis', **kwargs):
        """
        Инициализирует хранилище на основе указанного бэкенда.

        :param backend: Название бэкенда ('redis', 'memcache', etc.)
        :param kwargs: Дополнительные параметры для конкретного бэкенда
        """
        self.backend = backend.lower()
        self.store = self._initialize_store(**kwargs)

    def _initialize_store(self, **kwargs):
        if self.backend == 'redis':
            return RedisStore(**kwargs)
        else:
            raise ValueError(f"Unsupported backend: {self.backend}")

    def get(self, key: str):
        return self.store.get(key)

    def cache_get(self, key: str):
        return self.store.cache_get(key)

    def cache_set(self, key: str, value, expire: int):
        return self.store.cache_set(key, value, expire)
