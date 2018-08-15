from setuptools import setup

setup(
    name='msoffcrypto-tool',
    version='4.5.0',
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
        'olefile >= 0.44',
        'cryptography >= 2.0.0',
    ],
    test_require=[
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
