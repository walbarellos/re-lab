"""
core/cache.py — Cache Inteligente de Respostas.

Evita requisições redundantes ao mesmo endpoint durante uma sessão,
reduzindo o ruído na rede e acelerando a execução.
"""

from typing import Dict, Any, Optional
from collections import OrderedDict
import httpx
from .logger import logger

class ResponseCache:
    """
    Cache LRU (Least Recently Used) com limite de tamanho para evitar OOM.
    """
    def __init__(self, maxsize: int = 1000):
        self.maxsize = maxsize
        self._cache: OrderedDict[str, httpx.Response] = OrderedDict()

    def _make_key(self, method: str, url: str, payload: Any = None, params: dict = None) -> str:
        # Gera chave única baseada no estado completo da requisição
        return f"{method.upper()}|{url}|{hash(str(payload))}|{hash(str(params))}"

    def get(self, method: str, url: str, payload: Any = None, params: dict = None) -> Optional[httpx.Response]:
        key = self._make_key(method, url, payload, params)
        if key in self._cache:
            # Move para o fim para manter a ordem LRU
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def set(self, method: str, url: str, response: httpx.Response, payload: Any = None, params: dict = None):
        key = self._make_key(method, url, payload, params)
        if key in self._cache:
            self._cache.move_to_end(key)
        
        self._cache[key] = response
        
        # Remove a entrada mais antiga se exceder o limite
        if len(self._cache) > self.maxsize:
            self._cache.popitem(last=False)
            logger.debug("Cache limit atingido: removendo entrada mais antiga (LRU).")

    def clear(self):
        self._cache.clear()
