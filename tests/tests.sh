#!/usr/bin/env bash

python ms_offcrypto_tool.py -P Password1234_ tests/inputs/example_password.docx /tmp/example.docx
diff /tmp/example.docx tests/outputs/example.docx
