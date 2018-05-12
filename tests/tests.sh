#!/usr/bin/env bash

cd tests
msoffcrypto-tool -p Password1234_ inputs/example_password.docx /tmp/example.docx
diff /tmp/example.docx outputs/example.docx
