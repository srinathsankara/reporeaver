"""Packaging for reporeaver. Keep it simple."""

from setuptools import find_packages, setup

setup(
    name="reporeaver",
    version="0.2.0",
    packages=find_packages(include=["reporeaver", "reporeaver.*"]),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "yaml": ["pyyaml>=5.0"],
        "dashboard": ["fastapi>=0.100", "uvicorn>=0.20", "jinja2>=3.0"],
        "all": ["pyyaml>=5.0", "fastapi>=0.100", "uvicorn>=0.20", "jinja2>=3.0"],
    },
    entry_points={
        "console_scripts": [
            "reporeaver=reporeaver.cli:main",
        ],
    },
    include_package_data=True,
)
