"""Compile using the requested Python interpreter, without executing or writing pyc."""
import sys
import tokenize
with tokenize.open(sys.argv[1]) as stream:
    compile(stream.read(),sys.argv[1],'exec')
