"""Agent Kernel - Lifecycle management for all agents."""
import asyncio
import logging
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger("redteam.kernel")


class AgentState(Enum):
    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"
    STOPPED = "stopped"


@dataclass
class AgentHealth:
    state: AgentState = AgentState.IDLE
    last_heartbeat: float = 0.0
    error_count: int = 0
    total_tasks: int = 0
    total_duration_ms: float = 0.0
    cycles: int = 0

    @property
    def avg_latency_ms(self):
        if self.total_tasks == 0:
            return 0.0
        return self.total_duration_ms / self.total_tasks


class AgentKernel:
    def __init__(self):
        self.agents: Dict[str, Any] = {}
        self.health: Dict[str, AgentHealth] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._running = False
        self.start_time = time.time()

    def register(self, name: str, agent: Any) -> None:
        self.agents[name] = agent
        self.health[name] = AgentHealth()
        logger.info(f"Registered agent: {name}")

    async def start_all(self) -> None:
        self._running = True
        for name, agent in self.agents.items():
            try:
                if hasattr(agent, "start"):
                    await agent.start()
                self.health[name].state = AgentState.RUNNING
                self.health[name].last_heartbeat = time.time()
                if hasattr(agent, "run_loop"):
                    self._tasks[name] = asyncio.create_task(
                        self._agent_loop(name, agent)
                    )
                logger.info(f"Started agent: {name}")
            except Exception as e:
                self.health[name].state = AgentState.ERROR
                self.health[name].error_count += 1
                logger.error(f"Failed to start {name}: {e}")

    async def _agent_loop(self, name: str, agent: Any) -> None:
        while self._running:
            try:
                start = time.time()
                await agent.run_loop()
                elapsed = (time.time() - start) * 1000
                self.health[name].total_tasks += 1
                self.health[name].total_duration_ms += elapsed
                self.health[name].cycles += 1
                self.health[name].last_heartbeat = time.time()
            except Exception as e:
                self.health[name].error_count += 1
                self.health[name].state = AgentState.ERROR
                logger.error(f"Agent {name} error: {e}")
                await asyncio.sleep(5)
                self.health[name].state = AgentState.RUNNING

    async def stop_all(self) -> None:
        self._running = False
        for name, task in self._tasks.items():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        for name, agent in self.agents.items():
            try:
                if hasattr(agent, "stop"):
                    await agent.stop()
                self.health[name].state = AgentState.STOPPED
            except Exception as e:
                logger.error(f"Error stopping {name}: {e}")

    async def dispatch(self, agent_name: str, payload: dict) -> dict:
        if agent_name not in self.agents:
            return {"error": f"Agent '{agent_name}' not found"}
        agent = self.agents[agent_name]
        health = self.health[agent_name]
        start = time.time()
        try:
            result = await agent.execute(payload)
            elapsed = (time.time() - start) * 1000
            health.total_tasks += 1
            health.total_duration_ms += elapsed
            health.last_heartbeat = time.time()
            return result
        except Exception as e:
            health.error_count += 1
            logger.error(f"Dispatch error for {agent_name}: {e}")
            return {"error": str(e)}

    def get_health(self) -> dict:
        result = {}
        for name, h in self.health.items():
            result[name] = {
                "status": h.state.value,
                "last_heartbeat": h.last_heartbeat,
                "cycles": h.cycles,
                "errors": h.error_count,
                "avg_latency_ms": round(h.avg_latency_ms, 2),
                "total_tasks": h.total_tasks,
            }
        return result

    def get_uptime(self) -> float:
        return time.time() - self.start_time
