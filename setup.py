from setuptools import setup

setup(name='ciborg',
      version='0.1',
      description='Automated CI/CD takeover and post-exploitation tool',
      url='https://github.com/phikshun/ciborg',
      author='phikshun',
      author_email='phikshun@users.noreply.github.com',
      license='MIT',
      packages=['ciborg'],
      entry_points = {
          'console_scripts': ['ciborg=ciborg.command_line:main'],
      }
      zip_safe=False)
