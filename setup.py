from setuptools import setup, find_packages

setup(
    name="netscan",
    version="0.1.0",
    packages=find_packages(),
    package_dir={"": "src"},
    install_requires=[
        "scapy==2.6.1",
        "python-nmap==0.7.1",
        "netifaces==0.11.0",
        "mac-vendor-lookup==0.1.12",
        "tabulate==0.9.0",
        "aiofiles",
        "aiohttp",
        "ping3==4.0.4",
    ],
    entry_points={
        'console_scripts': [
            'netscan=netscan.main:main',
        ],
    },
    python_requires=">=3.6",
)
