from distutils.core import setup
import py2exe

setup(
    console=['mdap.py'],
    options={'py2exe': {'bundle_files': 1, 'compressed': True}},
    zipfile=None
)
