# -*- mode: python ; coding: utf-8 -*-
import io
import subprocess

with io.open("malwarebazaar/__init__.py", "a") as fh:
    commit = subprocess.check_output(["git", "describe", "--always", "--tags", "--long"]).decode("utf-8").strip().split("-")[-1][1:]
    fh.write(f"commit = \"{commit}\"\n")

a = Analysis(['../../malwarebazaar/bazaar.py'],
             pathex=['bazaar'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='bazaar',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True )
