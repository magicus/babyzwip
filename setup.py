# Always prefer setuptools over distutils
from setuptools import setup, find_packages

from glob import glob
from os.path import basename
from os.path import splitext

setup(
    name='babyzwip',
    version='0.1',
    description='Z-Wave In Python',
    url='https://github.com/magicus/babyzwip',
    author='Magnus Ihse Bursie',
    author_email='mag@icus.se',
    license='GPL3',

    packages=find_packages(where="src"),
    package_dir={"": "src"},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],

    install_requires=['pyserial'],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
)
