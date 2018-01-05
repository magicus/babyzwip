# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

setup(
    name='babyzwip',
    version='0.1',
    description='Z-Wave In Python',
    url='https://github.com/magicus/babyzwip',
    author='Magnus Ihse Bursie',
    author_email='mag@icus.se',
    license='GPL3',

    packages=find_packages(exclude=['tests']),

    install_requires=['pyserial'],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
)
