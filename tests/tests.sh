#!/usr/bin/env bash

msoffcrypto-tool -P Password1234_ tests/inputs/example_password.docx /tmp/example.docx
diff /tmp/example.docx tests/outputs/example.docx
