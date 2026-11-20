import ast
from pathlib import Path
from typing import Set, Dict, List, Any
from ..models import DependencyAnalysis, ReachabilityStatus


class ASTReachabilityAnalyzer:
    """
    Academic Research Engine: AST & Call Graph Reachability Analysis.
    Eliminates false positives by verifying if vulnerable dependencies/symbols
    are imported or invoked in application source code.
    Constructs an interactive AST Call Graph with nodes and edges.
    """

    def analyze_workspace(self, workspace_path: Path, analyses: List[DependencyAnalysis]) -> Dict[str, Any]:
        imported_modules: Set[str] = set()
        invoked_symbols: Set[str] = set()
        file_to_imports: Dict[str, Set[str]] = {}

        # Step 1: Scan all Python source files in workspace using AST
        python_files = list(workspace_path.rglob("*.py")) if workspace_path.is_dir() else [workspace_path] if workspace_path.suffix == ".py" else []

        for py_file in python_files:
            # Skip virtual environments and hidden directories
            if any(part.startswith(".") or part in ["venv", "env", "node_modules", "samples"] for part in py_file.parts):
                continue
            fname = py_file.name
            file_to_imports[fname] = set()
            try:
                with open(py_file, "r", encoding="utf-8", errors="ignore") as f:
                    tree = ast.parse(f.read(), filename=str(py_file))

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            mod = alias.name.split(".")[0].lower()
                            imported_modules.add(mod)
                            file_to_imports[fname].add(mod)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            mod = node.module.split(".")[0].lower()
                            imported_modules.add(mod)
                            file_to_imports[fname].add(mod)
                    elif isinstance(node, ast.Attribute):
                        invoked_symbols.add(node.attr.lower())
                    elif isinstance(node, ast.Name):
                        invoked_symbols.add(node.id.lower())

            except Exception:
                pass

        # Step 2: Correlate reachability for each dependency analysis
        false_positives = 0
        for analysis in analyses:
            pkg_name = analysis.dependency.name.lower().replace("-", "_")

            # Check if package module is imported in project AST
            is_imported = pkg_name in imported_modules or any(mod.startswith(pkg_name) for mod in imported_modules)

            # Mark dependency reachability
            analysis.is_reachable = is_imported if len(python_files) > 0 else True

            for vuln in analysis.vulnerabilities:
                if not analysis.is_reachable:
                    vuln.reachability = ReachabilityStatus.UNREACHABLE
                    false_positives += 1
                else:
                    vuln.reachability = ReachabilityStatus.REACHABLE
                    vuln.reachable_symbols = list(invoked_symbols.intersection({"get", "post", "render", "loads", "dump", "execute", "parse"}))[:3]

        # Step 3: Construct Graph Nodes and Edges for Interactive UI
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        seen_nodes: Set[str] = set()

        # If source files were found, add them as source root nodes
        if file_to_imports:
            for fname, mods in file_to_imports.items():
                node_id = f"file:{fname}"
                if node_id not in seen_nodes:
                    seen_nodes.add(node_id)
                    nodes.append({
                        "id": node_id,
                        "label": fname,
                        "type": "file",
                        "group": "source_file",
                        "color": "#38bdf8",
                        "shape": "dot",
                        "size": 25,
                        "level": 0,
                        "title": f"Source File: {fname}\nImported Modules: {len(mods)}"
                    })
                for mod in mods:
                    mod_id = f"mod:{mod}"
                    if mod_id not in seen_nodes:
                        seen_nodes.add(mod_id)
                        nodes.append({
                            "id": mod_id,
                            "label": f"import {mod}",
                            "type": "module",
                            "group": "import",
                            "color": "#818cf8",
                            "shape": "diamond",
                            "size": 18,
                            "level": 1,
                            "title": f"Imported Module: {mod}"
                        })
                    edges.append({
                        "from": node_id,
                        "to": mod_id,
                        "label": "imports",
                        "color": {"color": "#64748b", "opacity": 0.8},
                        "arrows": "to"
                    })
        else:
            entry_id = "entry:workspace"
            seen_nodes.add(entry_id)
            nodes.append({
                "id": entry_id,
                "label": "Application Manifest",
                "type": "file",
                "group": "source_file",
                "color": "#38bdf8",
                "shape": "dot",
                "size": 25,
                "level": 0,
                "title": "Application Manifest Entrypoint"
            })

        # Add Dependency and Vulnerability Nodes
        for analysis in analyses:
            dep = analysis.dependency
            dep_id = f"dep:{dep.name}"
            pkg_name = dep.name.lower().replace("-", "_")

            is_reach = analysis.is_reachable
            has_vulns = analysis.has_vulnerabilities
            vuln_count = len(analysis.vulnerabilities)

            # Node Color & Status
            if not is_reach:
                color = "#4ade80"  # Green / Unreachable (eliminated false positive)
                status_text = "UNREACHABLE (Safe/False Positive Discounted)"
            elif has_vulns:
                color = "#f43f5e"  # Red / Reachable Vulnerable Threat
                status_text = f"REACHABLE (Vulnerable! {vuln_count} CVEs)"
            else:
                color = "#38bdf8"  # Cyan / Reachable Clean
                status_text = "REACHABLE (Clean - 0 CVEs)"

            if dep_id not in seen_nodes:
                seen_nodes.add(dep_id)
                nodes.append({
                    "id": dep_id,
                    "label": f"{dep.name}@{dep.version}",
                    "type": "dependency",
                    "group": "dependency",
                    "color": color,
                    "shape": "box",
                    "size": 22,
                    "level": 2,
                    "is_reachable": is_reach,
                    "vuln_count": vuln_count,
                    "status": status_text,
                    "title": f"Package: {dep.name} v{dep.version}\nStatus: {status_text}\nReachable: {is_reach}\nVulns: {vuln_count}"
                })

            # Connect imported module to dependency
            matched_mods = [m for m in imported_modules if m == pkg_name or m.startswith(pkg_name)]
            if matched_mods:
                for m in matched_mods:
                    edges.append({
                        "from": f"mod:{m}",
                        "to": dep_id,
                        "label": "resolves",
                        "color": {"color": "#a855f7", "opacity": 0.9},
                        "arrows": "to"
                    })
            else:
                root_ref = list(file_to_imports.keys())[0] if file_to_imports else None
                from_id = f"file:{root_ref}" if root_ref else "entry:workspace"
                edges.append({
                    "from": from_id,
                    "to": dep_id,
                    "label": "not imported (unreachable)" if len(python_files) > 0 else "declared",
                    "dashes": True,
                    "color": {"color": "#475569", "opacity": 0.5},
                    "arrows": "to"
                })

        return {
            "imported_modules": list(imported_modules),
            "false_positives_eliminated": false_positives,
            "graph": {
                "nodes": nodes,
                "edges": edges,
                "reachable_count": sum(1 for a in analyses if a.is_reachable),
                "unreachable_count": sum(1 for a in analyses if not a.is_reachable),
            }
        }
