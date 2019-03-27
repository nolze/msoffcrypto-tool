#!/usr/bin/env bash

set -ev

cd tests
msoffcrypto-tool -p Password1234_ inputs/example_password.docx /tmp/example.docx
diff /tmp/example.docx outputs/example.docx
msoffcrypto-tool -p Password1234_ inputs/example_password.xlsx /tmp/example.xlsx
diff /tmp/example.xlsx outputs/example.xlsx
msoffcrypto-tool -p Password1234_ inputs/ecma376standard_password.docx /tmp/ecma376standard_password_plain.docx
diff /tmp/ecma376standard_password_plain.docx outputs/ecma376standard_password_plain.docx
msoffcrypto-tool -p Password1234_ inputs/rc4cryptoapi_password.doc /tmp/rc4cryptoapi_password_plain.doc
diff /tmp/rc4cryptoapi_password_plain.doc outputs/rc4cryptoapi_password_plain.doc
msoffcrypto-tool -p Password1234_ inputs/rc4cryptoapi_password.xls /tmp/rc4cryptoapi_password_plain.xls
diff /tmp/rc4cryptoapi_password_plain.xls outputs/rc4cryptoapi_password_plain.xls
msoffcrypto-tool -p Password1234_ inputs/rc4cryptoapi_password.ppt /tmp/rc4cryptoapi_password_plain.ppt
diff /tmp/rc4cryptoapi_password_plain.ppt outputs/rc4cryptoapi_password_plain.ppt
