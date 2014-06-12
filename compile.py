#!/usr/bin/python3

import json
import os
import sys
import urllib.parse
import urllib.request

BASE_DIR = os.path.dirname(sys.argv[0])
CLOSURE_URL = 'http://closure-compiler.appspot.com/compile'
TARGET_JS = os.path.join(BASE_DIR, 'sample', 'chrome-nfc.js')

def print_errors(errors, js_files):
  for error in errors:
    if error['file'].lower().find('externs') >= 0:
      filename = error['file']
    else:
      fileno = int(error['file'][6:])
      filename = js_files[fileno]
    if 'error' in error:
      text = error['error']
    else:
      text = error['warning']
    print(filename + ':' + str(error['lineno']) + ' ' + text)
    print(error['line'])
    print()


JS_FILES = [
  'src/b64.js',
  'src/mifare-classic.js',
  'src/ndef.js',
  'src/nfc.js',
  'src/devmanager.js',
  'src/scl3711.js',
  'src/sha256.js',
  'src/tag.js',
  'src/tt2.js',
  'src/usb.js',
  'src/util.js'
]

def main():
  print('Compiling JavaScript code.')

  params = [
      ('compilation_level', 'WHITESPACE_ONLY'),
      ('formatting', 'pretty_print'),
      ('language', 'ECMASCRIPT5'),
      ('output_format', 'json'),
      ('output_info', 'statistics'),
      ('output_info', 'warnings'),
      ('output_info', 'errors'),
      ('output_info', 'compiled_code')
    ]

  for js_file in JS_FILES:
    params.append(('js_code', open(os.path.join(BASE_DIR, js_file)).read()))

  params = bytes(urllib.parse.urlencode(params, encoding='utf8'), 'utf8')
  headers = {'Content-Type': 'application/x-www-form-urlencoded'}

  print('Connecting', CLOSURE_URL)
  out = urllib.request.urlopen(CLOSURE_URL, data=params)
  result = json.loads(out.read().decode('utf8'))

  if 'errors' in result and len(result['errors']):
    print('Errors:')
    print_errors(result['errors'], JS_FILES)

  if 'warnings' in result and len(result['warnings']):
    print('Warnings:')
    print_errors(result['warnings'], JS_FILES)

  print('Writing', TARGET_JS)
  open(TARGET_JS, 'w').write(result['compiledCode'])

if __name__ == '__main__':
  main()
