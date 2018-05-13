#!/usr/bin/env bash

cd tests
msoffcrypto-tool -p Password1234_ inputs/example_password.docx /tmp/example.docx
diff /tmp/example.docx outputs/example.docx
msoffcrypto-tool -p Password1234_ inputs/example_password.xlsx /tmp/example.xlsx
diff /tmp/example.docx outputs/example.docx
