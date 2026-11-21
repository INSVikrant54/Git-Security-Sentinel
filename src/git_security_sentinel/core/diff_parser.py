"""
Git Security Sentinel - Unified Diff Parser.
Extracts added lines, target file paths, and accurate line numbers from git diffs.
"""

import re
from typing import Any, Dict, List, Optional


class UnifiedDiffParser:
    """
    Parses unified diff output to extract added lines, their target filenames,
    and accurate line numbers in the modified file.
    """

    @staticmethod
    def parse(diff_content: str) -> List[Dict[str, Any]]:
        """
        Returns a list of added line objects:
        [
            {
                "file": "path/to/file.py",
                "line": 42,
                "content": "new line content without leading '+'"
            }
        ]
        """
        added_lines: List[Dict[str, Any]] = []
        current_file: Optional[str] = None
        new_line_num: int = 0
        in_hunk: bool = False

        diff_file_pattern = re.compile(r"^diff --git a/(.*) b/(.*)$")
        hunk_header_pattern = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

        for raw_line in diff_content.splitlines():
            # Check for new file diff header
            diff_match = diff_file_pattern.match(raw_line)
            if diff_match:
                # b/ filename (spaces in filenames supported)
                current_file = diff_match.group(2)
                in_hunk = False
                continue

            if raw_line.startswith("+++ "):
                # Handle newly created files where diff --git may be followed by +++ b/filename
                plus_path = raw_line[4:].strip()
                if plus_path == "/dev/null":
                    current_file = None  # file deleted
                elif plus_path.startswith("b/"):
                    current_file = plus_path[2:]
                continue

            if raw_line.startswith("--- "):
                continue

            # Check for binary files
            if raw_line.startswith("Binary files "):
                in_hunk = False
                continue

            # Check for hunk header
            hunk_match = hunk_header_pattern.match(raw_line)
            if hunk_match:
                in_hunk = True
                new_line_num = int(hunk_match.group(1))
                continue

            if not in_hunk or not current_file:
                continue

            # Process hunk content
            if raw_line.startswith("+"):
                # Added line
                content = raw_line[1:]
                added_lines.append(
                    {
                        "file": current_file,
                        "line": new_line_num,
                        "content": content,
                    }
                )
                new_line_num += 1
            elif raw_line.startswith("-"):
                # Removed line - ignore for security scanning added changes
                pass
            elif raw_line.startswith(" "):
                # Context line
                new_line_num += 1
            elif raw_line.startswith("\\ No newline at end of file"):
                pass

        return added_lines
