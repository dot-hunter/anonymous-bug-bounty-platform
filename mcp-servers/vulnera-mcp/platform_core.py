#!/usr/bin/env python3
"""
Autonomous Security Research Platform — Core Modules.
Phase B: Planner | Phase C: Memory | Phase D: Knowledge Graph.
"""

from __future__ import annotations
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Any, Optional

logger = logging.getLogger("platform-core")

DATA_DIR = Path.home() / ".config" / "platform"
DATA_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Phase C: Long-Term Memory
# ---------------------------------------------------------------------------

class LongTermMemory:
    """Persistent memory for continuous learning across investigations."""

    def __init__(self, memory_dir=None):
        self.memory_dir = memory_dir or (DATA_DIR / "memory")
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.programs_file = self.memory_dir / "programs.jsonl"
        self.assets_file = self.memory_dir / "assets.jsonl"
        self.observations_file = self.memory_dir / "observations.jsonl"
        self.lessons_file = self.memory_dir / "lessons.jsonl"
        self.workflows_file = self.memory_dir / "workflows.jsonl"

    def record_program(self, program_data: dict):
        """Record a program analysis."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "program",
            "data": program_data,
        }
        self._append(self.programs_file, entry)

    def record_asset(self, asset_data: dict):
        """Record a discovered asset."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "asset",
            "data": asset_data,
        }
        self._append(self.assets_file, entry)

    def record_observation(self, observation: dict):
        """Record an observation during investigation."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "observation",
            "data": observation,
        }
        self._append(self.observations_file, entry)

    def record_lesson(self, lesson: dict):
        """Record a lesson learned."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "lesson",
            "data": lesson,
        }
        self._append(self.lessons_file, entry)

    def record_workflow(self, workflow: dict):
        """Record a workflow outcome."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "workflow",
            "data": workflow,
        }
        self._append(self.workflows_file, entry)

    def get_programs(self, limit=100):
        """Get recent program analyses."""
        return self._read_recent(self.programs_file, limit)

    def get_assets(self, program=None, limit=100):
        """Get discovered assets, optionally filtered by program."""
        assets = self._read_recent(self.assets_file, limit * 2)
        if program:
            assets = [a for a in assets if a.get("data", {}).get("program") == program]
        return assets[:limit]

    def get_observations(self, asset=None, limit=100):
        """Get observations, optionally filtered by asset."""
        observations = self._read_recent(self.observations_file, limit * 2)
        if asset:
            observations = [o for o in observations if o.get("data", {}).get("asset") == asset]
        return observations[:limit]

    def get_lessons(self, category=None, limit=50):
        """Get lessons learned, optionally filtered by category."""
        lessons = self._read_recent(self.lessons_file, limit * 2)
        if category:
            lessons = [l for l in lessons if l.get("data", {}).get("category") == category]
        return lessons[:limit]

    def search(self, query: str, types=None):
        """Search across all memory."""
        results = []
        files = {
            "programs": self.programs_file,
            "assets": self.assets_file,
            "observations": self.observations_file,
            "lessons": self.lessons_file,
            "workflows": self.workflows_file,
        }
        if types:
            files = {k: v for k, v in files.items() if k in types}

        for name, filepath in files.items():
            if filepath.exists():
                for line in filepath.read_text().splitlines():
                    if line.strip() and query.lower() in line.lower():
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        return results

    def _append(self, filepath: Path, entry: dict):
        """Append a JSONL entry."""
        with filepath.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def _read_recent(self, filepath: Path, limit: int):
        """Read recent entries from a JSONL file."""
        if not filepath.exists():
            return []
        entries = []
        for line in filepath.read_text().splitlines():
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return entries[-limit:]


# ---------------------------------------------------------------------------
# Phase D: Knowledge Graph
# ---------------------------------------------------------------------------

class KnowledgeGraphContinuously:
    """Continuously evolving knowledge graph for security research."""

    def __init__(self, graph_file=None):
        self.graph_file = graph_file or (DATA_DIR / "knowledge_graph.json")
        self.nodes = {}
        self.edges = {}
        self.metadata = {
            "created": datetime.utcnow().isoformat(),
            "version": "2.0",
            "total_nodes": 0,
            "total_edges": 0,
        }
        self._load()

    def _load(self):
        """Load graph from disk."""
        if self.graph_file.exists():
            try:
                data = json.loads(self.graph_file.read_text())
                self.nodes = data.get("nodes", {})
                self.edges = data.get("edges", {})
                self.metadata = data.get("metadata", self.metadata)
            except (json.JSONDecodeError, OSError):
                pass

    def _save(self):
        """Save graph to disk."""
        self.metadata["total_nodes"] = len(self.nodes)
        self.metadata["total_edges"] = sum(len(v) for v in self.edges.values())
        self.metadata["last_updated"] = datetime.utcnow().isoformat()
        data = {
            "nodes": self.nodes,
            "edges": self.edges,
            "metadata": self.metadata,
        }
        self.graph_file.write_text(json.dumps(data, indent=2, default=str))

    def add_node(self, node_id: str, node_type: str, data: dict = None):
        """Add or update a node."""
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "data": data or {},
                "created": datetime.utcnow().isoformat(),
                "updated": datetime.utcnow().isoformat(),
                "version": 1,
            }
        else:
            self.nodes[node_id]["data"].update(data or {})
            self.nodes[node_id]["updated"] = datetime.utcnow().isoformat()
            self.nodes[node_id]["version"] += 1
        self._save()
        return self.nodes[node_id]

    def add_edge(self, source: str, target: str, edge_type: str, data: dict = None):
        """Add a directed edge."""
        if source not in self.edges:
            self.edges[source] = {}
        self.edges[source][target] = {
            "type": edge_type,
            "data": data or {},
            "created": datetime.utcnow().isoformat(),
        }
        self._save()

    def get_node(self, node_id: str) -> Optional[dict]:
        """Get a node by ID."""
        return self.nodes.get(node_id)

    def get_edges(self, node_id: str, direction="out") -> list:
        """Get edges for a node."""
        edges = []
        if direction in ["out", "both"]:
            if node_id in self.edges:
                for target, edge_data in self.edges[node_id].items():
                    edges.append({"source": node_id, "target": target, **edge_data})
        if direction in ["in", "both"]:
            for source, targets in self.edges.items():
                if node_id in targets:
                    edges.append({"source": source, "target": node_id, **targets[node_id]})
        return edges

    def query(self, node_type=None, edge_type=None, data_filter=None) -> list:
        """Query the graph."""
        results = []
        for node_id, node in self.nodes.items():
            if node_type and node["type"] != node_type:
                continue
            if data_filter:
                match = True
                for key, value in data_filter.items():
                    if node.get("data", {}).get(key) != value:
                        match = False
                        break
                if not match:
                    continue
            results.append(node)
        return results

    def find_path(self, source: str, target: str, max_depth=5) -> list:
        """Find a path between two nodes (BFS)."""
        visited = {source}
        queue = [(source, [source])]
        while queue:
            current, path = queue.pop(0)
            if current == target:
                return path
            if len(path) >= max_depth:
                continue
            if current in self.edges:
                for neighbor in self.edges[current]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, path + [neighbor]))
        return []

    def get_subgraph(self, node_id: str, depth=2) -> dict:
        """Get a subgraph centered on a node."""
        visited = {node_id}
        frontier = {node_id}
        for _ in range(depth):
            new_frontier = set()
            for node in frontier:
                if node in self.edges:
                    for neighbor in self.edges[node]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            new_frontier.add(neighbor)
                for source, targets in self.edges.items():
                    if node in targets and source not in visited:
                        visited.add(source)
                        new_frontier.add(source)
            frontier = new_frontier

        return {
            "nodes": {n: self.nodes[n] for n in visited if n in self.nodes},
            "edges": {s: {t: e for t, e in edges.items() if t in visited} for s, edges in self.edges.items() if s in visited},
        }

    def get_statistics(self) -> dict:
        """Get graph statistics."""
        node_types = defaultdict(int)
        edge_types = defaultdict(int)
        for node in self.nodes.values():
            node_types[node["type"]] += 1
        for source_edges in self.edges.values():
            for edge in source_edges.values():
                edge_types[edge["type"]] += 1
        return {
            "total_nodes": len(self.nodes),
            "total_edges": sum(len(v) for v in self.edges.values()),
            "node_types": dict(node_types),
            "edge_types": dict(edge_types),
        }


# ---------------------------------------------------------------------------
# Phase B: Goal-Driven Planner
# ---------------------------------------------------------------------------

class GoalDrivenPlanner:
    """Autonomous planner that generates and prioritizes investigation goals."""

    def __init__(self, memory: LongTermMemory, knowledge_graph: KnowledgeGraphContinuously):
        self.memory = memory
        self.kg = knowledge_graph
        self.goals = []
        self.completed_goals = []
        self.current_goal = None
        self.planner_state_file = DATA_DIR / "planner_state.json"
        self._load_state()

    def _load_state(self):
        """Load planner state."""
        if self.planner_state_file.exists():
            try:
                state = json.loads(self.planner_state_file.read_text())
                self.goals = state.get("goals", [])
                self.completed_goals = state.get("completed_goals", [])
            except (json.JSONDecodeError, OSError):
                pass

    def _save_state(self):
        """Save planner state."""
        state = {
            "goals": self.goals,
            "completed_goals": self.completed_goals[-100:],  # Keep last 100
            "current_goal": self.current_goal,
            "last_updated": datetime.utcnow().isoformat(),
        }
        self.planner_state_file.write_text(json.dumps(state, indent=2, default=str))

    def generate_goals(self, target: str, scope: dict) -> list:
        """Generate investigation goals based on target and scope."""
        goals = []

        # Phase 1: Reconnaissance
        goals.append({
            "id": f"recon_{hashlib.md5(target.encode()).hexdigest()[:8]}",
            "phase": "reconnaissance",
            "title": f"Enumerate subdomains for {target}",
            "description": "Passive and active subdomain enumeration",
            "priority": 10,
            "status": "pending",
            "tools": ["subdomain_enum", "recon"],
            "estimated_time": 120,
        })

        goals.append({
            "id": f"live_{hashlib.md5(target.encode()).hexdigest()[:8]}",
            "phase": "reconnaissance",
            "title": f"Probe live hosts for {target}",
            "description": "HTTP probing and technology fingerprinting",
            "priority": 9,
            "status": "pending",
            "depends_on": [f"recon_{hashlib.md5(target.encode()).hexdigest()[:8]}"],
            "tools": ["live_probe"],
            "estimated_time": 60,
        })

        # Phase 2: Technology Analysis
        goals.append({
            "id": f"tech_{hashlib.md5(target.encode()).hexdigest()[:8]}",
            "phase": "analysis",
            "title": f"Fingerprint technologies for {target}",
            "description": "Identify frameworks, servers, and libraries",
            "priority": 8,
            "status": "pending",
            "depends_on": [f"live_{hashlib.md5(target.encode()).hexdigest()[:8]}"],
            "tools": ["httpx", "nmap"],
            "estimated_time": 90,
        })

        # Phase 3: Vulnerability Assessment
        goals.append({
            "id": f"vuln_{hashlib.md5(target.encode()).hexdigest()[:8]}",
            "phase": "vulnerability",
            "title": f"Scan for known vulnerabilities on {target}",
            "description": "Nuclei template scanning and CVE matching",
            "priority": 7,
            "status": "pending",
            "depends_on": [f"live_{hashlib.md5(target.encode()).hexdigest()[:8]}"],
            "tools": ["nuclei", "scan_cves"],
            "estimated_time": 180,
        })

        # Phase 4: Deep Analysis
        goals.append({
            "id": f"deep_{hashlib.md5(target.encode()).hexdigest()[:8]}",
            "phase": "deep_analysis",
            "title": f"Deep analysis of {target} endpoints",
            "description": "API analysis, JS review, parameter testing",
            "priority": 6,
            "status": "pending",
            "depends_on": [f"tech_{hashlib.md5(target.encode()).hexdigest()[:8]}"],
            "tools": ["js_analyze", "param_discover", "api_test"],
            "estimated_time": 300,
        })

        # Phase 5: Authorization Testing
        goals.append({
            "id": f"auth_{hashlib.md5(target.encode()).hexdigest()[:8]}",
            "phase": "authorization",
            "title": f"Test authorization controls on {target}",
            "description": "IDOR, BOLA, BFLA, privilege escalation",
            "priority": 5,
            "status": "pending",
            "depends_on": [f"deep_{hashlib.md5(target.encode()).hexdigest()[:8]}"],
            "tools": ["test_idor", "bola_direct_id", "api_bfla"],
            "estimated_time": 600,
        })

        self.goals = goals
        self._save_state()
        return goals

    def next_goal(self) -> Optional[dict]:
        """Get the next highest-priority goal that is ready to execute."""
        pending = [g for g in self.goals if g["status"] == "pending"]
        if not pending:
            return None

        # Filter goals whose dependencies are met
        ready = []
        for goal in pending:
            deps = goal.get("depends_on", [])
            deps_met = all(
                any(g["id"] == dep and g["status"] == "completed" for g in self.goals)
                for dep in deps
            )
            if deps_met:
                ready.append(goal)

        if not ready:
            return None

        # Sort by priority (highest first)
        ready.sort(key=lambda g: g.get("priority", 0), reverse=True)
        return ready[0]

    def complete_goal(self, goal_id: str, result: dict):
        """Mark a goal as completed."""
        for goal in self.goals:
            if goal["id"] == goal_id:
                goal["status"] = "completed"
                goal["result"] = result
                goal["completed_at"] = datetime.utcnow().isoformat()
                self.completed_goals.append(goal)
                break
        self._save_state()

    def replan(self, observation: dict):
        """Re-plan based on new observation."""
        # Add new goals based on observations
        if observation.get("type") == "new_endpoint":
            self.goals.append({
                "id": f"endpoint_{hashlib.md5(observation.get('url', '').encode()).hexdigest()[:8]}",
                "phase": "analysis",
                "title": f"Analyze new endpoint: {observation.get('url', 'unknown')}",
                "priority": 7,
                "status": "pending",
                "tools": ["test_xss", "test_sqli", "test_ssrf"],
                "estimated_time": 120,
            })
        self._save_state()

    def get_status(self) -> dict:
        """Get planner status."""
        return {
            "total_goals": len(self.goals),
            "completed": len([g for g in self.goals if g["status"] == "completed"]),
            "pending": len([g for g in self.goals if g["status"] == "pending"]),
            "current_goal": self.current_goal,
        }


# ---------------------------------------------------------------------------
# Phase E: Hypothesis Engine
# ---------------------------------------------------------------------------

class HypothesisEngine:
    """Generate and rank research hypotheses."""

    def __init__(self, knowledge_graph: KnowledgeGraphContinuously):
        self.kg = knowledge_graph
        self.hypotheses = []

    def generate_hypotheses(self, target: str, evidence: dict) -> list:
        """Generate hypotheses based on collected evidence."""
        hypotheses = []

        # Analyze technologies for known weaknesses
        techs = evidence.get("technologies", [])
        for tech in techs:
            if "WordPress" in tech:
                hypotheses.append({
                    "id": f"wp_plugin_vuln_{hashlib.md5(target.encode()).hexdigest()[:8]}",
                    "hypothesis": "Outdated WordPress plugins may be vulnerable",
                    "confidence": 0.6,
                    "priority": 8,
                    "tests": ["enumerator_plugins", "check_plugin_versions"],
                })
            if "Spring" in tech:
                hypotheses.append({
                    "id": f"spring_actuator_{hashlib.md5(target.encode()).hexdigest()[:8]}",
                    "hypothesis": "Spring Boot actuator endpoints may be exposed",
                    "confidence": 0.5,
                    "priority": 7,
                    "tests": ["check_actuator", "check_env_endpoint"],
                })
            if "React" in tech or "Vue" in tech or "Angular" in tech:
                hypotheses.append({
                    "id": f"spa_api_{hashlib.md5(target.encode()).hexdigest()[:8]}",
                    "hypothesis": "SPA may have unprotected API endpoints",
                    "confidence": 0.4,
                    "priority": 6,
                    "tests": ["crawl_js", "test_api_auth"],
                })

        # Analyze endpoints for authorization issues
        endpoints = evidence.get("endpoints", [])
        for ep in endpoints:
            if any(param in ep for param in ["id", "user_id", "order_id", "account_id"]):
                hypotheses.append({
                    "id": f"idor_{hashlib.md5(ep.encode()).hexdigest()[:8]}",
                    "hypothesis": f"Endpoint {ep} may have IDOR/BOLA vulnerability",
                    "confidence": 0.5,
                    "priority": 9,
                    "tests": ["bola_direct_id", "bola_body_idor", "test_idor"],
                })
            if any(param in ep for param in ["url", "uri", "redirect", "callback"]):
                hypotheses.append({
                    "id": f"ssrf_{hashlib.md5(ep.encode()).hexdigest()[:8]}",
                    "hypothesis": f"Endpoint {ep} may be vulnerable to SSRF/open redirect",
                    "confidence": 0.4,
                    "priority": 8,
                    "tests": ["test_ssrf", "ssrf_dns_rebinding"],
                })

        # Sort by priority and confidence
        hypotheses.sort(key=lambda h: (h["priority"], h["confidence"]), reverse=True)
        self.hypotheses = hypotheses
        return hypotheses

    def rank_hypotheses(self) -> list:
        """Rank hypotheses by expected value (confidence * priority)."""
        for h in self.hypotheses:
            h["expected_value"] = h["confidence"] * h["priority"]
        self.hypotheses.sort(key=lambda h: h.get("expected_value", 0), reverse=True)
        return self.hypotheses

    def get_top_hypothesis(self) -> Optional[dict]:
        """Get the top-ranked hypothesis."""
        ranked = self.rank_hypotheses()
        return ranked[0] if ranked else None


# ---------------------------------------------------------------------------
# Phase F: Evidence-Based Reasoning
# ---------------------------------------------------------------------------

class EvidenceCollector:
    """Collect and structure evidence during investigation."""

    def __init__(self, evidence_dir=None):
        self.evidence_dir = evidence_dir or (DATA_DIR / "evidence")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.findings_file = self.evidence_dir / "findings.jsonl"
        self.evidence_index_file = self.evidence_dir / "evidence_index.json"

    def record_evidence(self, evidence: dict):
        """Record a piece of evidence."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "evidence": evidence,
        }
        with self.findings_file.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def add_finding(self, finding: dict):
        """Add a validated finding."""
        finding["recorded_at"] = datetime.utcnow().isoformat()
        finding["confidence"] = finding.get("confidence", "medium")
        finding["status"] = finding.get("status", "pending_review")
        with self.findings_file.open("a") as f:
            f.write(json.dumps(finding, default=str) + "\n")

    def get_findings(self, status=None, limit=100):
        """Get findings, optionally filtered by status."""
        findings = []
        if self.findings_file.exists():
            for line in self.findings_file.read_text().splitlines():
                if line.strip():
                    try:
                        finding = json.loads(line)
                        if status and finding.get("status") != status:
                            continue
                        findings.append(finding)
                    except json.JSONDecodeError:
                        pass
        return findings[-limit:]

    def update_confidence(self, finding_id: str, new_confidence: str, reason: str):
        """Update confidence in a finding."""
        # This would update the finding in place in a real DB
        pass


# ---------------------------------------------------------------------------
# Phase J: Reliability
# ---------------------------------------------------------------------------

class ReliabilityManager:
    """Manage checkpointing, retries, and circuit breaking."""

    def __init__(self, state_dir=None):
        self.state_dir = state_dir or (DATA_DIR / "reliability")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_file = self.state_dir / "checkpoint.json"
        self.circuit_file = self.state_dir / "circuit_breakers.json"
        self.circuit_breakers = self._load_circuit_breakers()

    def _load_circuit_breakers(self) -> dict:
        """Load circuit breaker state."""
        if self.circuit_file.exists():
            try:
                return json.loads(self.circuit_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_circuit_breakers(self):
        """Save circuit breaker state."""
        self.circuit_file.write_text(json.dumps(self.circuit_breakers, indent=2))

    def checkpoint(self, state: dict):
        """Save a checkpoint."""
        state["checkpoint_time"] = datetime.utcnow().isoformat()
        self.checkpoint_file.write_text(json.dumps(state, indent=2, default=str))

    def restore_checkpoint(self) -> Optional[dict]:
        """Restore from last checkpoint."""
        if self.checkpoint_file.exists():
            try:
                return json.loads(self.checkpoint_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return None

    def check_circuit(self, tool_name: str) -> bool:
        """Check if a tool's circuit is closed (allowed to run)."""
        if tool_name not in self.circuit_breakers:
            return True
        cb = self.circuit_breakers[tool_name]
        if cb["state"] == "open":
            # Check if cooldown has elapsed
            last_failure = datetime.fromisoformat(cb["last_failure"])
            if datetime.utcnow() - last_failure > timedelta(seconds=cb.get("cooldown", 60)):
                cb["state"] = "half-open"
                self._save_circuit_breakers()
                return True
            return False
        return True

    def record_success(self, tool_name: str):
        """Record a successful tool execution."""
        if tool_name in self.circuit_breakers:
            self.circuit_breakers[tool_name]["failures"] = 0
            self.circuit_breakers[tool_name]["state"] = "closed"
            self._save_circuit_breakers()

    def record_failure(self, tool_name: str):
        """Record a tool failure."""
        if tool_name not in self.circuit_breakers:
            self.circuit_breakers[tool_name] = {
                "failures": 0,
                "state": "closed",
                "last_failure": None,
                "cooldown": 60,
            }
        self.circuit_breakers[tool_name]["failures"] += 1
        self.circuit_breakers[tool_name]["last_failure"] = datetime.utcnow().isoformat()
        if self.circuit_breakers[tool_name]["failures"] >= 5:
            self.circuit_breakers[tool_name]["state"] = "open"
        self._save_circuit_breakers()

    def execute_with_retry(self, func, *args, max_retries=3, **kwargs):
        """Execute a function with retry logic."""
        for attempt in range(max_retries):
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 5  # Exponential backoff
                    logger.warning(f"Retry {attempt + 1}/{max_retries} after {wait_time}s: {e}")
                    time.sleep(wait_time)
                else:
                    raise


# ---------------------------------------------------------------------------
# Phase H: Event System for Multi-Agent Communication
# ---------------------------------------------------------------------------

class EventBus:
    """Event bus for inter-agent communication."""

    def __init__(self):
        self.listeners = defaultdict(list)
        self.event_log = []
        self.max_log_size = 10000

    def subscribe(self, event_type: str, callback):
        """Subscribe to an event type."""
        self.listeners[event_type].append(callback)

    def publish(self, event_type: str, data: dict):
        """Publish an event."""
        event = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.event_log.append(event)
        if len(self.event_log) > self.max_log_size:
            self.event_log = self.event_log[-self.max_log_size :]

        for callback in self.listeners.get(event_type, []):
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event handler error: {e}")

    def get_events(self, event_type=None, limit=100):
        """Get recent events."""
        events = self.event_log
        if event_type:
            events = [e for e in events if e["type"] == event_type]
        return events[-limit:]


# ---------------------------------------------------------------------------
# Platform Orchestrator
# ---------------------------------------------------------------------------

class PlatformOrchestrator:
    """Main orchestrator that ties all platform components together."""

    def __init__(self):
        self.memory = LongTermMemory()
        self.kg = KnowledgeGraphContinuously()
        self.planner = GoalDrivenPlanner(self.memory, self.kg)
        self.hypothesis = HypothesisEngine(self.kg)
        self.evidence = EvidenceCollector()
        self.reliability = ReliabilityManager()
        self.events = EventBus()
        self.active_investigations = {}

    def start_investigation(self, target: str, scope: dict) -> dict:
        """Start a new investigation."""
        investigation_id = hashlib.md5(f"{target}_{time.time()}".encode()).hexdigest()[:12]

        # Generate plan
        goals = self.planner.generate_goals(target, scope)

        # Record in knowledge graph
        self.kg.add_node(f"investigation:{investigation_id}", "investigation", {
            "target": target,
            "scope": scope,
            "started": datetime.utcnow().isoformat(),
        })

        # Record in memory
        self.memory.record_program({
            "target": target,
            "investigation_id": investigation_id,
            "goals_count": len(goals),
        })

        # Publish event
        self.events.publish("investigation_started", {
            "investigation_id": investigation_id,
            "target": target,
            "goals": len(goals),
        })

        self.active_investigations[investigation_id] = {
            "target": target,
            "scope": scope,
            "goals": goals,
            "status": "active",
            "started": datetime.utcnow().isoformat(),
        }

        return {
            "investigation_id": investigation_id,
            "goals": goals,
            "status": "started",
        }

    def get_next_action(self, investigation_id: str) -> Optional[dict]:
        """Get the next action for an investigation."""
        goal = self.planner.next_goal()
        if goal:
            self.planner.current_goal = goal
            return {"action": "execute_goal", "goal": goal}
        return None

    def report_progress(self) -> dict:
        """Report platform progress."""
        return {
            "active_investigations": len(self.active_investigations),
            "planner": self.planner.get_status(),
            "knowledge_graph": self.kg.get_statistics(),
            "events": len(self.events.event_log),
        }


# Singleton instance
_platform = None

def get_platform() -> PlatformOrchestrator:
    """Get the singleton platform instance."""
    global _platform
    if _platform is None:
        _platform = PlatformOrchestrator()
    return _platform
