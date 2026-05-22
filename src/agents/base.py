"""Abstract base agent."""
import asyncio
import logging
from abc import ABC, abstractmethod


class BaseAgent(ABC):
    def __init__(self):
        self.logger = logging.getLogger(f"redteam.{self.__class__.__name__}")
        self._running = False

    async def start(self):
        self._running = True
        self.logger.info(f"{self.__class__.__name__} started")

    async def stop(self):
        self._running = False
        self.logger.info(f"{self.__class__.__name__} stopped")

    @abstractmethod
    async def execute(self, payload: dict) -> dict:
        pass

    async def run_loop(self):
        await asyncio.sleep(self.interval)

    @property
    def interval(self) -> float:
        return 10.0
