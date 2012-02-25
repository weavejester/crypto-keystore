(ns crypto.test.keystore
  (:use clojure.test
        crypto.keystore))

(deftest test-keystore
  (is (instance? java.security.KeyStore (keystore))))