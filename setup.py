"""
Setup script for Automated Secrets Scanner
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="automated-secrets-scanner",
    version="1.0.0",
    author="Udit Agarwal",
    author_email="agarwalu@iu.edu",
    description="A DevSecOps tool for detecting hardcoded secrets in source code",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/automated-secrets-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "GitPython>=3.1.40",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pylint>=3.0.0",
            "black>=23.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "secrets-scanner=cli:main",
        ],
    },
    keywords="security devsecops secrets scanner credentials static-analysis",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/automated-secrets-scanner/issues",
        "Source": "https://github.com/yourusername/automated-secrets-scanner",
    },
)