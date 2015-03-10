from setuptools import setup, find_packages


setup(
    name="UtilityBelt",
    version="0.1",
    description="Utilities to make you a CND Batman",
    url="https://github.com/sroberts/utilitybelt",
    license="MIT",
    packages=find_packages(),
    package_data={'utilitybelt': ['data/GeoLiteCity.dat']},
    install_requires=['requests', 'GeoIP']
)
