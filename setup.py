from setuptools import setup
from setuptools import find_packages

about = {}
with open("./ranranru/__version__.py") as f:
    exec(f.read(), about)

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

REQUIREMENTS = [
    "click>=8,<9",
    "jinja2>=2,<3",
    "black",
]

setup(
    name="ranranru",
    python_requires=">=3.9",
    py_modules=["ranranru"],
    version=about["__version__"],
    long_description=long_description,
    license="GPL-3.0",
    description="Trace Golang with bcc like gdb",
    packages=find_packages(),
    entry_points={"console_scripts": ["rrr=ranranru.main:main"]},
    url="https://github.com/jschwinger23/ranranru",
    long_description_content_type="text/markdown",
    author_email="greyschwinger@gmail.com",
    install_requires=REQUIREMENTS,
    platform=("linux"),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Utilities",
    ],
    zip_safe=False,
)
