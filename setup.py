from setuptools import setup, find_packages

setup(
    name="web-sentinel",
    version="2.1.0",
    description="Modular Web Reconnaissance & Vulnerability Audit Toolkit in Pure Python",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Angga Pratama",
    url="https://github.com/anggalabs/web-sentinel",
    packages=find_packages(),
    py_modules=["sentinel"],
    entry_points={
        "console_scripts": [
            "web-sentinel=sentinel:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
