#!/usr/bin/env python3
"""
Dependency Synchronization Verification Script
Ensures pyproject.toml and requirements.txt have matching dependencies.
"""

import re
import sys
from pathlib import Path


def parse_requirements_txt(file_path: Path) -> dict[str, str]:
    """Parse requirements.txt and extract package==version mappings."""
    packages = {}
    if not file_path.exists():
        return packages
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip comments, empty lines, and commented dependencies
            if not line or line.startswith('#'):
                continue
            
            # Match package[extra]==version format
            match = re.match(r'^([a-zA-Z0-9_-]+)(\[[a-zA-Z0-9_,-]+\])?==([0-9.]+[a-zA-Z0-9._-]*)$', line)
            if match:
                package = match.group(1)
                extra = match.group(2) or ""
                version = match.group(3)
                packages[f"{package}{extra}"] = version
    
    return packages


def parse_pyproject_toml_dependencies(file_path: Path) -> dict[str, str]:
    """Parse pyproject.toml dependencies and extract package==version mappings."""
    packages = {}
    if not file_path.exists():
        return packages
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Find the dependencies array
    in_dependencies = False
    for line in content.split('\n'):
        line = line.strip()
        
        if line == 'dependencies = [':
            in_dependencies = True
            continue
        elif in_dependencies and line == ']':
            break
        elif in_dependencies and line.startswith('"') and line.endswith('",'):
            # Extract dependency string
            dep = line[1:-2]  # Remove quotes and comma
            
            # Match package[extra]==version format
            match = re.match(r'^([a-zA-Z0-9_-]+)(\[[a-zA-Z0-9_,-]+\])?==([0-9.]+[a-zA-Z0-9._-]*)$', dep)
            if match:
                package = match.group(1)
                extra = match.group(2) or ""
                version = match.group(3)
                packages[f"{package}{extra}"] = version
    
    return packages


def main():
    """Main verification function."""
    repo_root = Path(__file__).parent
    backend_dir = repo_root / "app" / "backend"
    
    pyproject_toml = backend_dir / "pyproject.toml"
    requirements_txt = backend_dir / "requirements.txt"
    
    print("🔍 Dependency Synchronization Verification")
    print("=" * 50)
    
    # Parse both files
    pyproject_deps = parse_pyproject_toml_dependencies(pyproject_toml)
    requirements_deps = parse_requirements_txt(requirements_txt)
    
    print(f"📦 pyproject.toml dependencies: {len(pyproject_deps)}")
    print(f"📦 requirements.txt dependencies: {len(requirements_deps)}")
    print()
    
    # Find differences
    pyproject_only = set(pyproject_deps.keys()) - set(requirements_deps.keys())
    requirements_only = set(requirements_deps.keys()) - set(pyproject_deps.keys())
    common_packages = set(pyproject_deps.keys()) & set(requirements_deps.keys())
    
    # Check version mismatches
    version_mismatches = []
    for package in common_packages:
        if pyproject_deps[package] != requirements_deps[package]:
            version_mismatches.append((
                package,
                pyproject_deps[package],
                requirements_deps[package]
            ))
    
    # Report results
    success = True
    
    if pyproject_only:
        print("⚠️  Packages only in pyproject.toml:")
        for pkg in sorted(pyproject_only):
            print(f"   - {pkg}=={pyproject_deps[pkg]}")
        success = False
        print()
    
    if requirements_only:
        print("⚠️  Packages only in requirements.txt:")
        for pkg in sorted(requirements_only):
            print(f"   - {pkg}=={requirements_deps[pkg]}")
        success = False
        print()
    
    if version_mismatches:
        print("⚠️  Version mismatches:")
        for pkg, pyproject_ver, req_ver in version_mismatches:
            print(f"   - {pkg}: pyproject.toml={pyproject_ver}, requirements.txt={req_ver}")
        success = False
        print()
    
    if success:
        print("✅ All dependencies are synchronized!")
        print(f"   - {len(common_packages)} packages have matching versions")
        print("   - No missing or extra dependencies found")
    else:
        print("❌ Dependency synchronization issues found!")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())