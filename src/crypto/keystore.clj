(ns crypto.keystore
  "Functions for creating and managing Java Keystores."
  (:require [clojure.java.io :as io])
  (:import java.security.KeyStore
           java.security.Security
           org.bouncycastle.openssl.PEMReader
           org.bouncycastle.openssl.PasswordFinder
           org.bouncycastle.jce.provider.BouncyCastleProvider))

(Security/addProvider (BouncyCastleProvider.))

(deftype Password [password]
  PasswordFinder
  (getPassword [_]
    (.toCharArray (str password))))

(defn pem-reader [file password]
  (PEMReader. (io/reader file) (Password. password)))

(defn keystore
  "Create a blank KeyStore."
  []
  (KeyStore/getInstance (KeyStore/getDefaultType)))