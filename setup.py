from setuptools import setup, find_packages

setup(
    name="netscan",
    version="0.1.0",
    description="Network Scanner - Discover, identify, and monitor devices on your network",
    author="Digital Dropkick, LLC",
    author_email="info@digitaldropkick.com",
    url="https://github.com/digitaldropkick/netscan",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "scapy==2.6.1",
        "python-nmap==0.7.1",
        "netifaces==0.11.0",
        "mac-vendor-lookup==0.1.12",
        "tabulate==0.9.0",
        "ping3==4.0.4",
        "flask>=2.0.0",
        "rich>=10.0.0",
    ],
    entry_points={
        'console_scripts': [
            'netscan=netscan.main:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    python_requires=">=3.6",
)
