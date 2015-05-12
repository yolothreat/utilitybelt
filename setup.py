from distutils.core import setup

setup(
    name="cnd-utilitybelt",
    packages=['utilitybelt'],
    version="0.2.1",
    description="Utilities to make you a CND Batman",
    url="https://github.com/yolothreat/utilitybelt",
    license="MIT",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Utilities'],
    include_package_data=True,
    install_requires=['requests>=2.6.0',
                      'pygeoip==0.3.2',
                      'pytest>=2.6.0',
                      'pytest-cov>=1.8.1',
                      'coveralls>=0.5',
                      'pre-commit>=0.4.4',
                      'BeautifulSoup4>=4.3.2',
                      'netaddr>=0.7.14'
                      ],
)
