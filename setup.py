import os
from setuptools import setup, find_packages

def get_readme():
    try:
        return open(os.path.join(os.path.dirname(__file__), 'README.md')).read()
    except IOError:
        return ''

setup(
    name = 'securitylib',
    version = '1.0.0',
    packages=find_packages(),
    install_requires = [
        'pycrypto',
    ],
    package_data = {
        '': ['*.txt', '*.md'],
    },

    author = 'Francisco José Marques Vieira',
    author_email = 'francisco.vieira@co.sapo.pt',
    url = 'http://trac.intra.sapo.pt/securitylib/',
    description = ('Functions/classes that solve common security related problems, while being easy to use even by those who are not security experts.'),
    long_description = get_readme(),
    license='GPL',
    keywords='',
    classifiers=[],
)
