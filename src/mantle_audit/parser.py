"""Solidity code parser using Slither."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

from slither import Slither
from slither.core.declarations import Function as SlitherFunction


@dataclass
class FunctionInfo:
    name: str
    visibility: str
    state_mutability: str
    parameters: list[str]
    return_type: list[str]
    line_start: int = 0
    line_end: int = 0
    modifiers: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)


@dataclass
class ContractInfo:
    name: str
    file_path: str
    functions: list[FunctionInfo] = field(default_factory=list)
    state_variables: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    inherits: list[str] = field(default_factory=list)


@dataclass
class ParseResult:
    contracts: list[ContractInfo] = field(default_factory=list)
    solidity_version: str = ""
    source_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @property
    def total_functions(self) -> int:
        return sum(len(c.functions) for c in self.contracts)

    @property
    def total_contracts(self) -> int:
        return len(self.contracts)


def _extract_function_info(func: SlitherFunction) -> FunctionInfo:
    """Extract structured info from a Slither function."""
    params = [str(p.type) + " " + p.name for p in func.parameters]
    returns = [str(r.type) for r in func.returns]
    modifiers = [m.name for m in func.modifiers]
    ext_calls = list(set(
        str(ir.function) if hasattr(ir, "function") else str(ir)
        for node in func.nodes
        for ir in node.irs
        if hasattr(ir, "function") and ir.function
    ))

    return FunctionInfo(
        name=func.name,
        visibility=str(func.visibility),
        state_mutability=str(func.state_mutability),
        parameters=params,
        return_type=returns,
        line_start=func.source_mapping.lines[0] if func.source_mapping.lines else 0,
        line_end=func.source_mapping.lines[-1] if func.source_mapping.lines else 0,
        modifiers=modifiers,
        external_calls=ext_calls[:10],  # cap to avoid noise
    )


def parse_contract(sol_path: str) -> ParseResult:
    """Parse a Solidity file and return structured contract info.

    Args:
        sol_path: Path to the .sol file.

    Returns:
        ParseResult with contracts, versions, and any errors.
    """
    result = ParseResult()
    path = Path(sol_path)

    if not path.exists():
        result.errors.append(f"File not found: {sol_path}")
        return result

    try:
        slither = Slither(str(path))
    except Exception as e:
        result.errors.append(f"Slither parse error: {e}")
        return result

    # Extract Solidity version pragma
    try:
        with open(path) as f:
            for line in f:
                if "pragma solidity" in line:
                    result.solidity_version = line.strip().rstrip(";")
                    break
    except Exception:
        pass

    result.source_files.append(str(path))

    for contract in slither.contracts:
        functions = []
        for func in contract.functions:
            if func.contract_declarer == contract:  # only own functions
                try:
                    functions.append(_extract_function_info(func))
                except Exception:
                    continue  # skip functions that fail to parse

        state_vars = [v.name for v in contract.state_variables]
        modifiers = [m.name for m in contract.modifiers]
        events = [e.name for e in contract.events]
        inherits = [i.name for i in contract.inheritance]

        result.contracts.append(ContractInfo(
            name=contract.name,
            file_path=str(path),
            functions=functions,
            state_variables=state_vars,
            modifiers=modifiers,
            events=events,
            inherits=inherits,
        ))

    return result
