#!/usr/bin/env bash

cd tests
msoffcrypto-tool -p Password1234_ inputs/example_password.docx /tmp/example.docx
diff /tmp/example.docx outputs/example.docx
msoffcrypto-tool -p Password1234_ inputs/example_password.xlsx /tmp/example.xlsx
diff /tmp/example.xlsx outputs/example.xlsx
msoffcrypto-tool -p Password1234_ inputs/ecma376standard_password.docx /tmp/ecma376standard_password_plain.docx
diff /tmp/ecma376standard_password_plain.docx outputs/ecma376standard_password_plain.docx
