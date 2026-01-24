#!/usr/bin/env python3
"""
VPN Manager with Advanced Kill Switch
Setup configuration
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
if requirements_file.exists():
    with open(requirements_file) as f:
        requirements = [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith('#')
        ]
else:
    requirements = [
        'PyYAML>=6.0',
        'rich>=13.0.0',
        'requests>=2.31.0',
        'dnspython>=2.4.0',
        'click>=8.1.0'
    ]

setup(
    name="vpn-manager",
    version="1.0.0",
    author="VPN Manager Team",
    author_email="info@example.com",
    description="Advanced VPN Manager with Kill Switch for Linux",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/vpn-manager",
    packages=find_packages(exclude=['tests', 'tests.*']),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: End Users/Desktop",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
            'pytest-timeout>=2.1.0',
            'black>=23.7.0',
            'flake8>=6.1.0',
            'mypy>=1.5.0',
        ],
        'docs': [
            'sphinx>=7.1.0',
            'sphinx-rtd-theme>=1.3.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'vpn-manager=vpn_manager.cli.interface:main',
        ],
    },
    include_package_data=True,
    package_data={
        'vpn_manager': [
            'config/*.yaml',
            'config/*.json',
        ],
    },
    zip_safe=False,
    keywords='vpn openvpn wireguard kill-switch security privacy linux',
    project_urls={
        'Bug Reports': 'https://github.com/yourusername/vpn-manager/issues',
        'Source': 'https://github.com/yourusername/vpn-manager',
        'Documentation': 'https://github.com/yourusername/vpn-manager/wiki',
    },
)
