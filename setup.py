# Filename    : setup.py
# Author      : Jon Kelley <jonathan.kelley@logdna.com>
# Description : Support Team API to get data from the LogDNA Mongo Database with basic auth

from setuptools import setup, find_packages
from sys import path
from os import environ

path.insert(0, '.')

NAME = "rebrow"

if __name__ == "__main__":

    setup(
        name=NAME,
        version='0.0.1',
        author="Jonathan Kelley",
        author_email="jonk@omg.lol",
        url="https://github.com/jondkelley/rebrow-modernized",
        license='ASLv2',
        packages=find_packages(),
        include_package_data=True,
        package_dir={NAME: NAME},
        description="rebrow - Built for the developer who needs to browse a Redis store.",
        install_requires=['redis==3.3.11', 'Flask==1.1.0'],
        entry_points={
            'console_scripts': ['rebrow = rebrow.runserver:main'],
        },
        zip_safe=False,
    )
