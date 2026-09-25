import os
import tempfile
import requests
from pathlib import Path
from typing import Optional

GITHUB_RAW_URL = "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
GITHUB_API_REPO_URL = "https://api.github.com/repos/{owner}/{repo}/contents"


class GitHubFetcher:
    """Fetches dependency manifests from a public or private GitHub repository."""

    MANIFEST_FILES = ["requirements.txt", "pyproject.toml", "package.json", "pom.xml"]

    def fetch_repo_manifests(self, github_url: str, branch: str = "main", token: Optional[str] = None) -> Path:
        """
        Downloads dependency manifest files from GitHub repo into a temporary workspace directory.
        """
        owner, repo = self._parse_github_url(github_url)
        temp_dir = Path(tempfile.mkdtemp(prefix="devsecops_gh_"))

        headers = {}
        if token:
            headers["Authorization"] = f"token {token}"

        downloaded = 0
        for manifest in self.MANIFEST_FILES:
            url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{manifest}"
            try:
                resp = requests.get(url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    file_path = temp_dir / manifest
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(resp.text)
                    downloaded += 1
            except Exception as e:
                print(f"[!] Warning fetching {manifest} from GitHub: {e}")

        if downloaded == 0:
            # Try master branch if main branch failed
            if branch == "main":
                return self.fetch_repo_manifests(github_url, branch="master", token=token)
            raise ValueError(f"No dependency manifest files found in GitHub repo {github_url}")

        return temp_dir

    def _parse_github_url(self, url: str) -> (str, str):
        cleaned = url.rstrip("/").replace("https://github.com/", "").replace("http://github.com/", "")
        parts = cleaned.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1].replace(".git", "")
        raise ValueError(f"Invalid GitHub repository URL: {url}")
