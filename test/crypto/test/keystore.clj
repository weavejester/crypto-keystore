(ns crypto.test.keystore
  (:use clojure.test
        crypto.keystore))

(def cert
  "-----BEGIN CERTIFICATE-----
MIICazCCAdQCCQDHAFAm5u+byTANBgkqhkiG9w0BAQUFADB6MQswCQYDVQQGEwJB
VTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMRIwEAYDVQQDEwlsb2NhbGhvc3QxHzAdBgkqhkiG9w0BCQEWEGpk
b2VAZXhhbXBsZS5jb20wHhcNMTIwMjI2MDA1NDM0WhcNMTMwMjI1MDA1NDM0WjB6
MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQDEwlsb2NhbGhvc3QxHzAdBgkq
hkiG9w0BCQEWEGpkb2VAZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0A
MIGJAoGBAKScQ69saqCk8Vjd7PE+Axh69M1fkF0BSwSiCEntwCNRYIsW5xQJD2NW
kUUzWprBwFCRJydtVaXJY3blMGeF1XhRz67peMJd0FcMJ9GcZDDdHKPg5uzmflin
fJ3KVFMcdlxCeZqyHE4+sVpxlrymskjOYw2q/rsLUYVmgOHSK/gxAgMBAAEwDQYJ
KoZIhvcNAQEFBQADgYEAY/3l3tc219ActsJt3kx0nBbw0E+eW7Viu6HQratFFDDy
w/05Vl77em01r0qeIPp7icT5x+e03q09iNhf+g7s2/AJiDW1P4mw9/fcpRnfCiQM
LGYjZrCIk1W/s+57P3wjTOB2My8K/DCWIX4DIt1DbbA1k0PqpMlpKu+ueP9bvoA=
-----END CERTIFICATE-----
")

(deftest test-keystore
  (is (instance? java.security.KeyStore (keystore))))

(defmacro with-keystore [type file password & body]
  `(let [~'ks (keystore ~type ~file ~password)]
     ~@body))

(deftest test-entry-count-empty_ks
  (let [ks (keystore)
        entries (load-entries ks)]
    (is (= 0 (count (:entries entries))))))

(deftest test-certificates-empty_ks
  (let [ks (keystore)]
    (import-cert ks "test-cert" cert)
    (is (= cert (export-cert ks "test-cert")))))
