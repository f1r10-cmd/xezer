"""Discoverable strategy interface; adding a plugin never edits the orchestrator."""
from __future__ import annotations

from dataclasses import dataclass, field
import importlib
import pkgutil
from typing import Protocol

from .context import TestContext


@dataclass(frozen=True)
class TestPlan:
    __test__ = False
    vuln_class: str
    request_id: int | None
    prerequisite_hash: str
    reason: str
    missing_prerequisites: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    methods: tuple[str, ...] = ('GET',)


@dataclass
class TestResult:
    __test__ = False
    status: str
    reason: str
    evidence: list[dict] = field(default_factory=list)
    confirmed: bool = False


class TestStrategy(Protocol):
    vuln_class: str

    def is_applicable(self, context: TestContext) -> tuple[bool, str]: ...
    def plan_test(self, context: TestContext) -> TestPlan: ...
    async def execute_test(self, context: TestContext, plan: TestPlan) -> TestResult: ...


def discover(package='qbh.brain.strategies') -> dict[str, TestStrategy]:
    """Load only installed package modules, never a path supplied by HAR/YAML."""
    root = importlib.import_module(package)
    found = {}
    for module in sorted(pkgutil.iter_modules(root.__path__), key=lambda m: m.name):
        if module.name.startswith('_'):
            continue
        loaded = importlib.import_module(f'{package}.{module.name}')
        plugin = getattr(loaded, 'Strategy', None)
        if plugin is None:
            raise ValueError(f'plugin_missing_strategy:{module.name}')
        strategy = plugin()
        name = getattr(strategy, 'vuln_class', '')
        if not name or name in found or any(not callable(getattr(strategy, m, None))
                                            for m in ('is_applicable', 'plan_test', 'execute_test')):
            raise ValueError(f'invalid_or_duplicate_plugin:{module.name}')
        found[name] = strategy
    return found
