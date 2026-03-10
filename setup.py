from setuptools import setup, find_packages

setup(
    name="soc-automation",
    version="1.0.0",
    description="SOC Automation System using Python + AI with Wazuh, TheHive, and Shuffle",
    author="SOC Automation Team",
    python_requires=">=3.11",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "aiohttp>=3.9.0",
        "python-dotenv>=1.0.0",
        "pyyaml>=6.0.1",
        "scikit-learn>=1.3.0",
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        "thehive4py>=1.8.1",
        "jinja2>=3.1.2",
        "pydantic>=2.4.0",
        "schedule>=1.2.0",
        "openai>=1.0.0",
        "reportlab>=4.0",
        "stix2>=3.0.0",
        "taxii2-client>=2.3.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.12.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "soc-automation=src.main:main",
        ]
    },
)
