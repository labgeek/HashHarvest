# Legacy PDF cryptography

The PDF reader in `internal/readers/pdfcrypt.go` uses RC4 and MD5 to read
existing encrypted evidence. These algorithms are required by the legacy
PDF standard security handler: [ISO 32000-1:2008](https://opensource.adobe.com/dc-acrobat-sdk-docs/standards/pdfstandards/pdf/PDF32000_2008.pdf),
sections 7.6.2-7.6.3, Algorithms 1-7. Replacing them would prevent reading
those PDFs. MD5 also derives object keys for legacy AES-128 PDFs.

The reader accepts no caller-supplied password. It tries the empty user and
owner passwords; an empty owner password can recover a nonempty padded user
password from the document's existing owner entry. MD5 derives keys and
validation values in memory. RC4 decrypts owner entries and streams, and
encrypts fixed padding or its digest to compare against existing user entries.
This handler writes neither encrypted PDFs nor stored password hashes.

RC4 and MD5 are weak and must not be selected to protect new secrets. Their
use here provides compatibility with input files, not confidentiality or
integrity guarantees for evidence. The CodeQL RC4 and MD5 findings describe
required legacy operations, not newly protected data or application password
storage. This rationale is limited to these uses; it is not a claim that the
PDF parser or input files are free of other security risks.
