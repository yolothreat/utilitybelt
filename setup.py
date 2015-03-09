from setuptools import setup, find_packages

setup(
    name="UtilityBelt",
    version="0.1",
    description="Utilities to make you a CND Batman",
    url="https://github.com/sroberts/utilitybelt",
    license="MIT",
    packages=find_packages(),
    install_requires=['requests', 'GeoIP']
)
