from setuptools import setup
import codecs
import os
import re

here = os.path.abspath(os.path.dirname(__file__))

def read(*parts):
    with codecs.open(os.path.join(here, *parts), 'r') as fp:
        return fp.read()

# https://packaging.python.org/guides/single-sourcing-package-version/
def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

setup(
    name='msoffcrypto-tool',
    version=find_version("msoffcrypto", "__init__.py"),
    description='A Python tool and library for decrypting MS Office files with passwords or other keys',
    long_description=open("README.md", "r").read(),
    long_description_content_type='text/markdown',
    url='https://github.com/nolze/msoffcrypto-tool',
    author='nolze',
    author_email='nolze@archlinux.us',
    license='MIT',
    keywords='',
    packages=[
        "msoffcrypto",
        "msoffcrypto.format",
        "msoffcrypto.method",
    ],
    install_requires=[
        'olefile >= 0.45',
        'cryptography >= 2.3',
    ],
    tests_require=[
        'nose >= 1.3.7',
        'coverage >= 4.5.1', 
    ],
    classifiers=[
    ],
    entry_points={
        'console_scripts': [
            'msoffcrypto-tool = msoffcrypto.__main__:main',
        ],
    },
)
