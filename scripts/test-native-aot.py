"""Validate the Windows x64 Native AOT artifact and run the MCP contract suite."""
from pathlib import Path
import struct
import sys
import unittest


def main():
    if len(sys.argv) != 1:
        raise ValueError('This script accepts no arguments.')
    root = Path(__file__).resolve().parents[1]
    executable = root / 'artifacts' / 'command-entry-win-x64' / 'CommandEntry.exe'
    if not executable.is_file():
        raise FileNotFoundError(executable)
    with executable.open('rb') as source:
        header = source.read(4096)
    if header[:2] != b'MZ':
        raise ValueError('Expected a Windows PE executable.')
    pe = struct.unpack_from('<I', header, 0x3c)[0]
    if header[pe:pe + 4] != b'PE\0\0':
        raise ValueError('Invalid PE signature.')
    if struct.unpack_from('<H', header, pe + 4)[0] != 0x8664:
        raise ValueError('The published executable is not x64.')
    optional_header = pe + 24
    if struct.unpack_from('<H', header, optional_header)[0] != 0x20b:
        raise ValueError('Expected a PE32+ optional header.')
    clr_rva, clr_size = struct.unpack_from('<II', header, optional_header + 112 + 14 * 8)
    if clr_rva != 0 or clr_size != 0:
        raise ValueError('A managed CLR image was published instead of native code.')
    for name in ('CommandEntry.dll', 'CommandEntry.runtimeconfig.json'):
        if (executable.parent / name).exists():
            raise ValueError(f'Unexpected managed application companion: {name}')
    for name in ('invoke.ps1', 'check_powershell.ps1', 'check_python.py'):
        if not (executable.parent / name).is_file():
            raise FileNotFoundError(executable.parent / name)
    print(f'Native artifact: {executable} ({executable.stat().st_size} bytes)', flush=True)
    sys.path.insert(0, str(root))
    from tests import test_csharp_migration
    test_csharp_migration.EXE = executable
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_csharp_migration.CSharpMigrationTests)
    result = unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
