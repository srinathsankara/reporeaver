"""Packaging for reporeaver."""

from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("CHANGELOG.md", encoding="utf-8") as f:
    changelog = f.read()

setup(
    name="reporeaver",
    version="0.2.0",
    description="Pre-clone repo security scanner. Catches obfuscated payloads in SVGs, unicode tricks, C2 callbacks, supply-chain attacks, and CI/CD abuse.",
    long_description=long_description + "\n\n---\n\n" + changelog,
    long_description_content_type="text/markdown",
    author="Srinath Sankara",
    author_email="srinathsankara@users.noreply.github.com",
    url="https://github.com/srinathsankara/reporeaver",
    project_urls={
        "Source": "https://github.com/srinathsankara/reporeaver",
        "Bug Tracker": "https://github.com/srinathsankara/reporeaver/issues",
        "Changelog": "https://github.com/srinathsankara/reporeaver/blob/main/CHANGELOG.md",
    },
    license="MIT",
    packages=find_packages(include=["reporeaver", "reporeaver.*"]),
    python_requires=">=3.8",
    install_requires=[
        "pyyaml>=5.0",
    ],
    extras_require={
        "dashboard": ["fastapi>=0.100", "uvicorn>=0.20", "jinja2>=3.0"],
        "all": ["fastapi>=0.100", "uvicorn>=0.20", "jinja2>=3.0"],
        "dev": ["pytest>=7.0", "pytest-cov>=4.0"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Software Development :: Build Tools",
    ],
    entry_points={
        "console_scripts": [
            "reporeaver=reporeaver.cli:main",
        ],
    },
    include_package_data=True,
)
