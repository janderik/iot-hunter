from setuptools import setup, find_packages

setup(
    name="iot-hunter",
    version="1.0.0",
    author="janderik",
    description="IoT Device Discovery and Security Assessment Toolkit",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={"console_scripts": ["iot-hunter=cli:main"]},
    classifiers=["Programming Language :: Python :: 3", "License :: OSI Approved :: MIT License"],
)
