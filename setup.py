from setuptools import setup, find_packages

setup(
    name="xcrypt_hydra",
    version="2.0.1",  # ← Bumped version
    author="Dr Sulaiman",
    author_email="balogunsulaiman37@proton.me",
    description="A perfected encryption system for AI security using quantum-inspired chaos, matrix cryptography, and digital signatures.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/QuantumXCryptDr/xcrypt_hydra",
    project_urls={
        "Source": "https://github.com/QuantumXCryptDr/xcrypt_hydra",
        "Bug Tracker": "https://github.com/QuantumXCryptDr/xcrypt_hydra/issues",
    },
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "numpy",
        "sympy",
        "pycryptodome",
    ],
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "xcrypt=xcrypt_hydra.__main__:main"
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
