from setuptools import setup

setup(
    name='msoffcrypto-tool',
    version='2.1.0',
    description='A Python tool and library for decrypting MS Office files with passwords and other secrets',
    url='https://github.com/nolze/msoffcrypto-tool',
    author='nolze',
    author_email='nolze@archlinux.us',
    license='MIT',
    keywords='',
    packages=[
        "msoffcrypto",
    ],
    install_requires=[
        'olefile >= 0.44',
        'cryptography >= 2.0.0',
    ],
    classifiers=[
    ],
    entry_points={
        'console_scripts': [
            'msoffcrypto-tool = msoffcrypto.msoffcrypto:main',
        ],
    },
)
