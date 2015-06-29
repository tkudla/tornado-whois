from setuptools import setup, find_packages

try:
    with open('README.rst') as f:
        readme = f.read()
except IOError:
    readme = ''

setup(
    name="tornado-whois",
    version="0.3",
    keywords=["tornado", "whois", "tornado-whois", "asyncwhois"],
    description="Asynchronous python tornado whois client",

    long_description=readme,

    packages=find_packages(),

    classifiers=['Programming Language :: Python :: 2', 'Programming Language :: Python :: 2.7'],

    install_requires=["tornado>=3.0"],
    requires=["tornado (>=3.0)"],
)
