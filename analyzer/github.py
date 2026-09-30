import os
import tempfile
import requests
from pathlib import Path
from typing import Optional, List

GITHUB_RAW_URL = "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
GITHUB_TREE_API = "https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"


class GitHubFetcher:
    """Fetches dependency manifests from a public or private GitHub repository (including subfolders)."""

    MANIFEST_PATTERNS = [
        "requirements.txt", "pyproject.toml", "Pipfile",
        "package.json", "package-lock.json",
        "pom.xml", "build.gradle",
        "go.mod", "Cargo.lock",
        "vcpkg.json", "conanfile.txt", "conanfile.py"
    ]

    def fetch_repo_manifests(self, github_url: str, branch: str = "main", token: Optional[str] = None) -> Path:
        """
        Downloads dependency manifest files from GitHub repo into a temporary workspace directory.
        First tries recursive GitHub Git Tree API to find manifests in subdirectories.
        """
        owner, repo = self._parse_github_url(github_url)
        temp_dir = Path(tempfile.mkdtemp(prefix="devsecops_gh_"))

        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"

        # Try fetching full git tree recursively to locate all manifests
        downloaded = 0
        manifest_paths: List[str] = []

        try:
            tree_url = GITHUB_TREE_API.format(owner=owner, repo=repo, branch=branch)
            resp = requests.get(tree_url, headers=headers, timeout=10)
            if resp.status_code == 404 and branch == "main":
                # Fallback to master branch if main branch is not found
                branch = "master"
                tree_url = GITHUB_TREE_API.format(owner=owner, repo=repo, branch=branch)
                resp = requests.get(tree_url, headers=headers, timeout=10)

            if resp.status_code == 200:
                tree_data = resp.json().get("tree", [])
                for item in tree_data:
                    file_path = item.get("path", "")
                    filename = Path(file_path).name.lower()
                    if any(filename == p or filename.endswith(".req") for p in self.MANIFEST_PATTERNS):
                        manifest_paths.append(file_path)

        except Exception as e:
            print(f"[!] Warning fetching GitHub git tree: {e}")

        # Fallback to standard root files if tree API was restricted or empty
        if not manifest_paths:
            manifest_paths = self.MANIFEST_PATTERNS

        for rel_path in manifest_paths:
            raw_url = GITHUB_RAW_URL.format(owner=owner, repo=repo, branch=branch, file_path=rel_path)
            try:
                raw_resp = requests.get(raw_url, headers=headers, timeout=10)
                if raw_resp.status_code == 200:
                    local_dest = temp_dir / rel_path
                    local_dest.parent.mkdir(parents=True, exist_ok=True)
                    with open(local_dest, "w", encoding="utf-8") as f:
                        f.write(raw_resp.text)
                    downloaded += 1
            except Exception as e:
                print(f"[!] Warning downloading {rel_path}: {e}")

        if downloaded == 0:
            raise ValueError(
                f"No supported dependency manifest files found in GitHub repo '{github_url}' (branch: {branch}).\n"
                f"Note: Repositories written in C/Assembly (like Linux Kernel) do not use package manager manifests."
            )

        return temp_dir

    def _parse_github_url(self, url: str) -> (str, str):
        cleaned = url.rstrip("/").replace("https://github.com/", "").replace("http://github.com/", "")
        parts = cleaned.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1].replace(".git", "")
        raise ValueError(f"Invalid GitHub repository URL: {url}")
