from setuptools import setup, find_packages

setup(
    name="Naminter",
    version="1.0.0",
    author="3xp0rt",
    author_email="contact@3xp0rt.com",
    description="A description of your package and CLI tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/3xp0rt/Naminter",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "curl-cffi",
        "typer",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "naminter = src.cli:entry_point",
        ],
    },
)
