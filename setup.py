from setuptools import setup
from setuptools import find_packages

about = {}
with open('./gbt/__version__.py') as f:
    exec(f.read(), about)

REQUIREMENTS = [
    'click>=7,<8',
    'jinja2>=2,<3',
    'regex==2021.4.4',
]

setup(name='gbt',
      python_requires='>=3.7',
      version=about['__version__'],
      packages=find_packages(),
      entry_points={'console_scripts': ['gbt=gbt.main:main']},
      author_email='greyschwinger@gmail.com',
      install_requires=REQUIREMENTS,
      zip_safe=False)
