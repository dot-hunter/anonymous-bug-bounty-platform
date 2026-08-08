#!/usr/bin/env python3
"""
Program Intelligence MCP Server — Continuous program discovery, enrichment,
research dossier generation, technology knowledge graph, adaptive priority
scoring, change detection, and memory for autonomous bug bounty operations.

ADDITIVE: This server is entirely new. It does NOT replace any existing MCP.
It plugs into the existing architecture and enriches recon inputs.

Connector architecture: every connector outputs one normalized schema.
Supported: ProjectDiscovery Public Programs, FireBounty, Security.txt Discovery,
Standalone Programs, and Future Connectors.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path

from mcp.server import MCPServer

# Add parent to path so we can import submodules
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from discovery.engine import DiscoveryEngine
from enrichment.enricher import ProgramEnricher
from research.research_agent import ResearchAgent
from scoring.priority_engine import PriorityEngine
from monitoring.change_detector import ChangeDetector
from memory.memory_store import MemoryStore
from adapters.adapter_registry import AdapterRegistry
from models.program import Program, ProgramSchema

# Authorized-discovery extension (providers, scope, WordPress, ranking)
import providers
from normalizer import ScopeNormalizer
from resolver import AuthorizationResolver
from wordpress import WordPressFingerprinter
from ranker import WordPressRanker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("program-intelligence")

# ── Data directories ──────────────────────────────────────────────────────────
DATA_DIR = Path.home() / ".config" / "program-intelligence"
DATA_DIR.mkdir(parents=True, exist_ok=True)
PROGRAMS_DB = DATA_DIR / "programs_db.json"
RESEARCH_DIR = DATA_DIR / "research"
RESEARCH_DIR.mkdir(exist_ok=True)
GRAPH_DB = DATA_DIR / "knowledge_graph.json"
MEMORY_DIR = DATA_DIR / "memory"
MEMORY_DIR.mkdir(exist_ok=True)
CHANGES_LOG = DATA_DIR / "changes.jsonl"
SNAPSHOTS_DIR = DATA_DIR / "snapshots"
SNAPSHOTS_DIR.mkdir(exist_ok=True)

# ── Initialize subsystems ─────────────────────────────────────────────────────
discovery = DiscoveryEngine(db_path=PROGRAMS_DB)
enricher = ProgramEnricher()
research_agent = ResearchAgent(research_dir=RESEARCH_DIR)
priority_engine = PriorityEngine()
change_detector = ChangeDetector(
    db_path=PROGRAMS_DB,
    changes_log=CHANGES_LOG,
    snapshots_dir=SNAPSHOTS_DIR,
)
memory_store = MemoryStore(memory_dir=MEMORY_DIR)
adapter_registry = AdapterRegistry()

# ── MCP Server ────────────────────────────────────────────────────────────────
server = MCPServer("program-intelligence")


# ──────────────────────────────────────────────────────────────────────────────
# DISCOVERY TOOLS
# ──────────────────────────────────────────────────────────────────────────────


@server.tool(
    name="discover_programs",
    description="Discover bug bounty programs from all configured connectors. Returns normalized program entries.",
)
def discover_programs(
    connector: str = "all",
    max_results: int = 50,
) -> dict:
    """Run discovery across connectors. connector='all' runs every connector."""
    try:
        results = discovery.discover(connector=connector, max_results=max_results)
        return {
            "status": "ok",
            "connector": connector,
            "programs_found": len(results),
            "programs": results,
        }
    except Exception as exc:
        logger.error("discover_programs error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="discover_new",
    description="Find programs not yet in the local database. Compare connectors against existing data.",
)
def discover_new(
    connector: str = "all",
    max_results: int = 50,
) -> dict:
    """Discover programs that are new (not in local DB)."""
    try:
        results = discovery.discover_new(connector=connector, max_results=max_results)
        return {
            "status": "ok",
            "connector": connector,
            "new_programs": len(results),
            "programs": results,
        }
    except Exception as exc:
        logger.error("discover_new error: %s", exc)
        return {"status": "error", "error": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# PROGRAM INTELLIGENCE TOOLS
# ──────────────────────────────────────────────────────────────────────────────


@server.tool(
    name="get_program",
    description="Get a single program by handle with full intelligence data, research dossier, and scoring.",
)
def get_program(handle: str) -> dict:
    """Retrieve a single program with all enriched intelligence."""
    try:
        prog = discovery.get_program(handle)
        if not prog:
            return {"status": "not_found", "handle": handle}
        return {"status": "ok", "program": prog}
    except Exception as exc:
        logger.error("get_program error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="list_programs",
    description="List all programs in the local intelligence database with optional filtering.",
)
def list_programs(
    platform: str | None = None,
    min_bounty: int | None = None,
    has_wildcard: bool | None = None,
    tag: str | None = None,
    max_results: int = 50,
) -> dict:
    """List programs with optional filters."""
    try:
        results = discovery.list_programs(
            platform=platform,
            min_bounty=min_bounty,
            has_wildcard=has_wildcard,
            tag=tag,
            max_results=max_results,
        )
        return {
            "status": "ok",
            "total": len(results),
            "programs": results,
        }
    except Exception as exc:
        logger.error("list_programs error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="enrich_program",
    description="Enrich a program with inferred technology intelligence: frameworks, cloud, CDN, auth, APIs. Never overwrites discovered data.",
)
def enrich_program(handle: str) -> dict:
    """Run the enricher on a single program. Adds intelligence, never overwrites."""
    try:
        prog = discovery.get_program(handle)
        if not prog:
            return {"status": "not_found", "handle": handle}
        enriched = enricher.enrich(prog)
        # Persist enriched data
        discovery.update_program(handle, enriched)
        return {
            "status": "ok",
            "handle": handle,
            "fields_added": enriched.get("_intelligence_added", []),
            "program": enriched,
        }
    except Exception as exc:
        logger.error("enrich_program error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="enrich_all",
    description="Enrich all programs in the local database with technology intelligence.",
)
def enrich_all(max_results: int = 50) -> dict:
    """Run enricher on all programs."""
    try:
        results = enricher.enrich_all(discovery, max_results=max_results)
        return {
            "status": "ok",
            "enriched_count": results["enriched"],
            "skipped_count": results["skipped"],
            "fields_added_total": results["fields_added_total"],
        }
    except Exception as exc:
        logger.error("enrich_all error: %s", exc)
        return {"status": "error", "error": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# RESEARCH DOSSIER TOOLS
# ──────────────────────────────────────────────────────────────────────────────


@server.tool(
    name="generate_research_dossier",
    description="Generate a research dossier for a program: collect docs, GitHub, OpenAPI, SDKs, DNS, cert transparency, subdomains, headers, framework detection.",
)
def generate_research_dossier(handle: str, force: bool = False) -> dict:
    """Generate or retrieve a cached research dossier."""
    try:
        prog = discovery.get_program(handle)
        if not prog:
            return {"status": "not_found", "handle": handle}
        dossier = research_agent.generate_dossier(
            program=prog,
            force=force,
        )
        return {
            "status": "ok",
            "handle": handle,
            "dossier": dossier,
        }
    except Exception as exc:
        logger.error("generate_research_dossier error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="get_research_dossier",
    description="Retrieve an existing research dossier for a program.",
)
def get_research_dossier(handle: str) -> dict:
    """Get cached dossier without regenerating."""
    try:
        dossier = research_agent.get_dossier(handle)
        if not dossier:
            return {"status": "not_found", "handle": handle}
        return {"status": "ok", "handle": handle, "dossier": dossier}
    except Exception as exc:
        logger.error("get_research_dossier error: %s", exc)
        return {"status": "error", "error": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# TECHNOLOGY KNOWLEDGE GRAPH TOOLS
# ──────────────────────────────────────────────────────────────────────────────


@server.tool(
    name="build_knowledge_graph",
    description="Build or rebuild the technology knowledge graph from all program intelligence data.",
)
def build_knowledge_graph() -> dict:
    """Build the knowledge graph connecting company/program/domain/technology/API/auth/cloud."""
    try:
        graph = _build_graph_from_programs()
        GRAPH_DB.write_text(json.dumps(graph, indent=2, default=str))
        return {
            "status": "ok",
            "nodes": len(graph.get("nodes", {})),
            "edges": len(graph.get("edges", {})),
            "graph": graph,
        }
    except Exception as exc:
        logger.error("build_knowledge_graph error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="query_knowledge_graph",
    description="Query the technology knowledge graph. Find programs by technology, domains by auth type, etc.",
)
def query_knowledge_graph(
    query_type: str = "by_technology",
    value: str = "",
    max_results: int = 20,
) -> dict:
    """Query the knowledge graph by type."""
    try:
        if not GRAPH_DB.exists():
            return {"status": "not_found", "error": "Graph not built yet. Call build_knowledge_graph first."}
        graph = json.loads(GRAPH_DB.read_text())
        results = _query_graph(graph, query_type=query_type, value=value, max_results=max_results)
        return {
            "status": "ok",
            "query_type": query_type,
            "value": value,
            "results": results,
        }
    except Exception as exc:
        logger.error("query_knowledge_graph error: %s", exc)
        return {"status": "error", "error": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# PRIORITY SCORING TOOLS
# ──────────────────────────────────────────────────────────────────────────────


@server.tool(
    name="score_program",
    description="Score a single program by priority. Inputs: attack surface, reward, scope breadth, docs, API presence, GraphQL, cloud assets, technology match, GitHub, recent changes. Output: priority score, tier, reasoning, recommended next action.",
)
def score_program(handle: str) -> dict:
    """Score a single program."""
    try:
        prog = discovery.get_program(handle)
        if not prog:
            return {"status": "not_found", "handle": handle}
        score = priority_engine.score_program(prog)
        return {
            "status": "ok",
            "handle": handle,
            "score": score,
        }
    except Exception as exc:
        logger.error("score_program error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="rank_programs",
    description="Rank all programs by priority score (highest first). Returns ordered list with scores, tiers, reasoning.",
)
def rank_programs(
    top_n: int = 20,
    platform: str | None = None,
    min_score: float | None = None,
) -> dict:
    """Rank all programs by priority."""
    try:
        ranked = priority_engine.rank_programs(
            discovery=discovery,
            top_n=top_n,
            platform=platform,
            min_score=min_score,
        )
        return {
            "status": "ok",
            "total_ranked": len(ranked),
            "programs": ranked,
        }
    except Exception as exc:
        logger.error("rank_programs error: %s", exc)
        return {"status": "error", "error": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# CHANGE DETECTION TOOLS
# ──────────────────────────────────────────────────────────────────────────────


@server.tool(
    name="detect_changes",
    description="Detect changes since last snapshot: new programs, removed programs, scope changes, reward changes, policy changes, asset changes, technology changes, documentation changes.",
)
def detect_changes() -> dict:
    """Run change detection against last snapshot."""
    try:
        changes = change_detector.detect()
        return {
            "status": "ok",
            "changes_detected": len(changes.get("changes", [])),
            "changes": changes,
        }
    except Exception as exc:
        logger.error("detect_changes error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="take_snapshot",
    description="Take a snapshot of the current program database for future change comparison.",
)
def take_snapshot() -> dict:
    """Save current state as snapshot."""
    try:
        snapshot = change_detector.take_snapshot()
        return {
            "status": "ok",
            "snapshot_time": snapshot["timestamp"],
            "program_count": snapshot["program_count"],
        }
    except Exception as exc:
        logger.error("take_snapshot error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="get_changes_history",
    description="Get historical change log entries.",
)
def get_changes_history(limit: int = 20) -> dict:
    """Get recent change log entries."""
    try:
        entries = change_detector.get_history(limit=limit)
        return {
            "status": "ok",
            "entries": entries,
        }
    except Exception as exc:
        logger.error("get_changes_history error: %s", exc)
        return {"status": "error", "error": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# MEMORY TOOLS
# ──────────────────────────────────────────────────────────────────────────────


@server.tool(
    name="save_memory",
    description="Save an entry to program memory. Types: program, research, recon, technology, framework, historical, pattern, success, failure, duplicate_avoidance.",
)
def save_memory(
    memory_type: str,
    key: str,
    data: dict,
) -> dict:
    """Save a memory entry."""
    try:
        memory_store.save(memory_type=memory_type, key=key, data=data)
        return {"status": "ok", "memory_type": memory_type, "key": key}
    except Exception as exc:
        logger.error("save_memory error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="get_memory",
    description="Retrieve a memory entry by type and key.",
)
def get_memory(memory_type: str, key: str) -> dict:
    """Get a memory entry."""
    try:
        entry = memory_store.get(memory_type=memory_type, key=key)
        if not entry:
            return {"status": "not_found", "memory_type": memory_type, "key": key}
        return {"status": "ok", "memory_type": memory_type, "key": key, "data": entry}
    except Exception as exc:
        logger.error("get_memory error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="search_memory",
    description="Search memory entries by type with optional value matching.",
)
def search_memory(
    memory_type: str,
    query: str = "",
    limit: int = 20,
) -> dict:
    """Search memory entries."""
    try:
        results = memory_store.search(memory_type=memory_type, query=query, limit=limit)
        return {"status": "ok", "memory_type": memory_type, "results": results}
    except Exception as exc:
        logger.error("search_memory error: %s", exc)
        return {"status": "error", "error": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# ADAPTER TOOLS (connect to existing MCP servers)
# ──────────────────────────────────────────────────────────────────────────────


@server.tool(
    name="register_adapter",
    description="Register a new connector adapter. Adapters plug into the discovery engine without modifying existing code.",
)
def register_adapter(
    name: str,
    adapter_type: str,
    config: dict | None = None,
) -> dict:
    """Register a new adapter."""
    try:
        adapter_registry.register(name=name, adapter_type=adapter_type, config=config or {})
        return {"status": "ok", "adapter": name, "type": adapter_type}
    except Exception as exc:
        logger.error("register_adapter error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="list_adapters",
        description="List all registered connector adapters.",
)
def list_adapters() -> dict:
    """List registered adapters."""
    try:
        adapters = adapter_registry.list_adapters()
        return {"status": "ok", "adapters": adapters}
    except Exception as exc:
        logger.error("list_adapters error: %s", exc)
        return {"status": "error", "error": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# STATS & STATUS
# ──────────────────────────────────────────────────────────────────────────────


@server.tool(
    name="get_stats",
        description="Get statistics about the program intelligence database.",
)
def get_stats() -> dict:
    """Get overall statistics."""
    try:
        stats = {
            "total_programs": discovery.count(),
            "platforms": discovery.count_by_platform(),
            "with_research": research_agent.count_dossiers(),
            "with_intelligence": discovery.count_enriched(),
            "memory_entries": memory_store.count(),
            "snapshots": change_detector.count_snapshots(),
            "changes_detected": change_detector.count_changes(),
            "adapters": adapter_registry.count(),
            "graph_built": GRAPH_DB.exists(),
        }
        return {"status": "ok", "stats": stats}
    except Exception as exc:
        logger.error("get_stats error: %s", exc)
        return {"status": "error", "error": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ──────────────────────────────────────────────────────────────────────────────


def _build_graph_from_programs() -> dict:
    """Build knowledge graph from all programs in DB."""
    programs = discovery.list_programs(max_results=10000)
    nodes: dict[str, dict] = {}
    edges: dict[str, dict[str, dict]] = {}

    for prog in programs:
        handle = prog.get("handle", "")
        if not handle:
            continue

        # Company/Program node
        company = prog.get("company", prog.get("name", handle))
        company_id = f"company:{company}"
        if company_id not in nodes:
            nodes[company_id] = {"id": company_id, "type": "company", "label": company}

        prog_id = f"program:{handle}"
        nodes[prog_id] = {
            "id": prog_id,
            "type": "program",
            "label": prog.get("name", handle),
            "platform": prog.get("platform", ""),
        }
        edges.setdefault(company_id, {})[prog_id] = {"type": "owns"}

        # Domain nodes
        for domain in prog.get("domains", []) or []:
            dom_id = f"domain:{domain}"
            if dom_id not in nodes:
                nodes[dom_id] = {"id": dom_id, "type": "domain", "label": domain}
            edges.setdefault(prog_id, {})[dom_id] = {"type": "has_domain"}

        # Technology nodes
        techs = prog.get("technology_stack", []) or []
        intelligence = prog.get("intelligence", {})
        if isinstance(intelligence, dict):
            for fw in intelligence.get("frameworks", []) or []:
                techs.append(fw)
        for tech in set(techs):
            tech_id = f"tech:{tech}"
            if tech_id not in nodes:
                nodes[tech_id] = {"id": tech_id, "type": "technology", "label": tech}
            edges.setdefault(prog_id, {})[tech_id] = {"type": "uses_tech"}

        # Auth nodes
        auth = prog.get("authentication", {}) or {}
        if isinstance(auth, dict):
            for auth_type in auth.get("types", []) or []:
                auth_id = f"auth:{auth_type}"
                if auth_id not in nodes:
                    nodes[auth_id] = {"id": auth_id, "type": "authentication", "label": auth_type}
                edges.setdefault(prog_id, {})[auth_id] = {"type": "uses_auth"}

        # Cloud nodes
        cloud = prog.get("cloud_assets", {}) or {}
        if isinstance(cloud, dict):
            for provider in cloud.get("providers", []) or []:
                cloud_id_node = f"cloud:{provider}"
                if cloud_id_node not in nodes:
                    nodes[cloud_id_node] = {"id": cloud_id_node, "type": "cloud", "label": provider}
                edges.setdefault(prog_id, {})[cloud_id_node] = {"type": "uses_cloud"}

        # API nodes
        apis = prog.get("public_apis", []) or []
        graphql = prog.get("graphql", []) or []
        for api in apis:
            api_id = f"api:{api}"
            if api_id not in nodes:
                nodes[api_id] = {"id": api_id, "type": "api", "label": api}
            edges.setdefault(prog_id, {})[api_id] = {"type": "exposes_api"}
        for gql in graphql:
            gql_id = f"graphql:{gql}"
            if gql_id not in nodes:
                nodes[gql_id] = {"id": gql_id, "type": "graphql", "label": gql}
            edges.setdefault(prog_id, {})[gql_id] = {"type": "exposes_graphql"}

        # Repository nodes
        repos = prog.get("github", []) or []
        if isinstance(repos, list):
            for repo in repos:
                repo_id = f"repo:{repo}"
                if repo_id not in nodes:
                    nodes[repo_id] = {"id": repo_id, "type": "repository", "label": repo}
                edges.setdefault(prog_id, {})[repo_id] = {"type": "has_repo"}

    return {"nodes": nodes, "edges": edges}


def _query_graph(
    graph: dict,
    query_type: str,
    value: str,
    max_results: int,
) -> list[dict]:
    """Query the knowledge graph."""
    nodes = graph.get("nodes", {})
    edges = graph.get("edges", {})
    results: list[dict] = []

    if query_type == "by_technology":
        # Find programs using a specific technology (searches all node types with partial match)
        value_lower = value.lower()
        for source, targets in edges.items():
            if not source.startswith("program:"):
                continue
            for target_id, edge_data in targets.items():
                # Extract the node name from the ID (e.g., "tech:react" -> "react")
                node_name = target_id.split(":", 1)[1] if ":" in target_id else target_id
                if value_lower in node_name.lower():
                    prog_node = nodes.get(source, {})
                    results.append({
                        "program": prog_node.get("label", source),
                        "handle": source.replace("program:", ""),
                        "relationship": edge_data.get("type", "related"),
                    })
                    break
            if len(results) >= max_results:
                break

    elif query_type == "by_authentication":
        auth_id = f"auth:{value}"
        for source, targets in edges.items():
            if auth_id in targets and source.startswith("program:"):
                prog_node = nodes.get(source, {})
                results.append({
                    "program": prog_node.get("label", source),
                    "handle": source.replace("program:", ""),
                    "relationship": targets[auth_id].get("type", "uses_auth"),
                })
                if len(results) >= max_results:
                    break

    elif query_type == "by_cloud":
        cloud_id = f"cloud:{value}"
        for source, targets in edges.items():
            if cloud_id in targets and source.startswith("program:"):
                prog_node = nodes.get(source, {})
                results.append({
                    "program": prog_node.get("label", source),
                    "handle": source.replace("program:", ""),
                    "relationship": targets[cloud_id].get("type", "uses_cloud"),
                })
                if len(results) >= max_results:
                    break

    elif query_type == "by_platform":
        for node_id, node in nodes.items():
            if node.get("type") == "program" and node.get("platform", "").lower() == value.lower():
                results.append({
                    "program": node.get("label", node_id),
                    "handle": node_id.replace("program:", ""),
                    "platform": node.get("platform", ""),
                })
                if len(results) >= max_results:
                    break

    elif query_type == "all_technologies":
        for node_id, node in nodes.items():
            if node.get("type") == "technology":
                results.append({
                    "technology": node.get("label", node_id),
                    "id": node_id,
                })
                if len(results) >= max_results:
                    break

    return results


# ──────────────────────────────────────────────────────────────────────────────
# AUTHORIZED DISCOVERY EXTENSION TOOLS
# (providers, scope normalization, authorization resolution, WordPress)
# ──────────────────────────────────────────────────────────────────────────────


@server.tool(
    name="normalize_scope",
    description="Normalize a program's scope into canonical form: domains, wildcards, assets, subdomains, out_of_scope. Purely syntactic, no testing.",
)
def normalize_scope(scope: dict | list | None = None, program: dict | None = None) -> dict:
    """Normalize heterogeneous scope input into a canonical dict."""
    try:
        if scope is None and program is None:
            return {"status": "error", "error": "Provide either scope or program"}
        raw = program or {}
        if scope is None:
            scope = raw.get("scope")
        normalized = ScopeNormalizer.normalize_scope(scope, raw)
        return {"status": "ok", "normalized_scope": normalized}
    except Exception as exc:
        logger.error("normalize_scope error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="resolve_authorization",
    description="Determine whether a target (hostname or URL) is authorized by a program's scope. Returns verdict: in_scope | out_of_scope | unknown with matching rule.",
)
def resolve_authorization(handle: str | None = None, target: str = "", program: dict | None = None) -> dict:
    """Resolve target authorization against a program's scope."""
    try:
        if program is None:
            if not handle:
                return {"status": "error", "error": "Provide handle or program"}
            prog = discovery.get_program(handle)
            if not prog:
                return {"status": "not_found", "handle": handle}
            program = prog
        if not target:
            return {"status": "error", "error": "target is required"}
        verdict = AuthorizationResolver.resolve_authorization(program, target)
        return {
            "status": "ok",
            "handle": program.get("handle"),
            "authorization": verdict,
        }
    except Exception as exc:
        logger.error("resolve_authorization error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="fingerprint_asset",
    description="Fingerprint a single authorized asset for WordPress: version, REST API, login page, plugins, themes. Only call on targets resolved in_scope.",
)
def fingerprint_asset(url: str = "", authorized: bool = False) -> dict:
    """Fingerprint one asset (must be authorized first)."""
    try:
        if not url:
            return {"status": "error", "error": "url is required"}
        if not authorized:
            return {
                "status": "error",
                "error": "Not authorized. Use resolve_authorization first; pass authorized=True only for in_scope targets.",
            }
        fp = WordPressFingerprinter(authorized=True).fingerprint(url, authorized=True)
        fp["status"] = "ok"
        return fp
    except Exception as exc:
        logger.error("fingerprint_asset error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="find_wordpress_assets",
    description="Fingerprint all in-scope domains/wildcards of a program for WordPress. Only authorized in-scope targets are probed.",
)
def find_wordpress_assets(handle: str = "", max_targets: int = 25) -> dict:
    """Find WordPress assets across a program's in-scope domains and wildcard hosts."""
    try:
        if not handle:
            return {"status": "error", "error": "handle is required"}
        prog = discovery.get_program(handle)
        if not prog:
            return {"status": "not_found", "handle": handle}

        scope = ScopeNormalizer.normalize_scope(prog.get("scope"), prog)
        candidates: list[str] = []

        # Exact domains are directly in scope.
        candidates.extend(d for d in scope.get("domains", []) if d)

        # Wildcards: probe the bare apex as the first candidate.
        for wc in scope.get("wildcards", []):
            apex = wc[2:] if wc.startswith("*.") else wc
            if apex and apex not in candidates:
                candidates.append(apex)

        # Subdomains discovered previously.
        candidates.extend(s for s in scope.get("subdomains", []) if s not in candidates)

        candidates = candidates[:max_targets]
        fp = WordPressFingerprinter(authorized=True, probe_plugins=True)
        results = []
        for target in candidates:
            if not target:
                continue
            fingerprint = fp.fingerprint(target, authorized=True)
            if fingerprint.get("is_wordpress"):
                results.append(fingerprint)

        return {
            "status": "ok",
            "handle": handle,
            "targets_probed": len(candidates),
            "wordpress_found": len(results),
            "assets": results,
        }
    except Exception as exc:
        logger.error("find_wordpress_assets error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="rank_wordpress_targets",
    description="Score and rank a program's WordPress targets. Base +30, +5/plugin (cap +20), +5 theme, +10 REST, +10 login, +15 bounty, +5 wildcard; cap 100.",
)
def rank_wordpress_targets(handle: str = "", max_targets: int = 25) -> dict:
    """Rank WordPress targets for a program by exploit-relevant features."""
    try:
        if not handle:
            return {"status": "error", "error": "handle is required"}
        prog = discovery.get_program(handle)
        if not prog:
            return {"status": "not_found", "handle": handle}

        found = find_wordpress_assets(handle, max_targets=max_targets)
        if found.get("status") != "ok":
            return found
        assets = found.get("assets", [])

        ranked = WordPressRanker.rank_program_targets(prog, assets)
        return {
            "status": "ok",
            "handle": handle,
            "wordpress_count": len(ranked),
            "ranked_targets": ranked,
        }
    except Exception as exc:
        logger.error("rank_wordpress_targets error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="get_target_provenance",
    description="Get provenance for a program's scope data: which provider/source contributed each entry, confidence, and last update.",
)
def get_target_provenance(handle: str = "") -> dict:
    """Return scope provenance for a program."""
    try:
        if not handle:
            return {"status": "error", "error": "handle is required"}
        prog = discovery.get_program(handle)
        if not prog:
            return {"status": "not_found", "handle": handle}

        scope = ScopeNormalizer.normalize_scope(prog.get("scope"), prog)
        source = prog.get("source", "unknown")
        platform = prog.get("platform", "unknown")
        confidence = prog.get("confidence", 0.5)

        provenance = {
            "handle": handle,
            "platform": platform,
            "source": source,
            "confidence": confidence,
            "last_updated": prog.get("last_updated"),
            "scope_entry_count": {
                "domains": len(scope.get("domains", [])),
                "wildcards": len(scope.get("wildcards", [])),
                "assets": len(scope.get("assets", [])),
                "out_of_scope": len(scope.get("out_of_scope", [])),
            },
        }

        # If source is a provider, annotate it.
        if str(source).startswith("provider:"):
            provider_name = str(source).split(":", 1)[-1]
            provenance["provider"] = provider_name
            provenance["note"] = (
                f"Data mirrored from {provider_name} public program page via "
                "authorized-discovery dataset (24h cache)."
            )

        # Memory may hold research provenance.
        mem = memory_store.get("research", handle)
        if mem:
            provenance["research_notes"] = mem

        return {"status": "ok", "provenance": provenance}
    except Exception as exc:
        logger.error("get_target_provenance error: %s", exc)
        return {"status": "error", "error": str(exc)}


@server.tool(
    name="get_scope_changes",
    description="Get scope changes for a program from the change history log (additions, removals, reward changes).",
)
def get_scope_changes(handle: str = "", limit: int = 20) -> dict:
    """Return scope change history for a program."""
    try:
        changes = change_detector.get_history(limit=limit)
        if handle:
            filtered = []
            for change in changes:
                if change.get("handle") == handle or change.get("program") == handle:
                    filtered.append(change)
            changes = filtered
        return {
            "status": "ok",
            "handle": handle or "all",
            "changes_found": len(changes),
            "changes": changes,
        }
    except Exception as exc:
        logger.error("get_scope_changes error: %s", exc)
        return {"status": "error", "error": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("Program Intelligence MCP Server starting")
    logger.info("Data dir: %s", DATA_DIR)
    logger.info("Programs DB: %s", PROGRAMS_DB)
    server.run()
