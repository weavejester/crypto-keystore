(ns crypto.keystore
  "Functions for creating and managing Java Keystores."
  (:require [clojure.java.io :as io])
  (:import java.io.StringReader
           java.security.KeyStore
           java.security.KeyStore$PrivateKeyEntry
           java.security.KeyPair
           java.security.PrivateKey
           java.security.Security
           java.security.cert.Certificate
           org.bouncycastle.openssl.PEMReader
           org.bouncycastle.openssl.PasswordFinder
           org.bouncycastle.jce.provider.BouncyCastleProvider))

(Security/addProvider (BouncyCastleProvider.))

(deftype PasswordFn [password-fn]
  PasswordFinder
  (getPassword [_]
    (.toCharArray (password-fn))))

(defprotocol PemSource
  (pem-reader [source pass-fn]
    "Create a PEMReader from a PEM source and optional password function."))

(extend-protocol PemSource
  String
  (pem-reader [s pass-fn] (pem-reader (StringReader. s) pass-fn))
  java.io.Reader
  (pem-reader [r pass-fn] (PEMReader. r (PasswordFn. pass-fn)))
  Object
  (pem-reader [x pass-fn] (pem-reader (io/reader x) pass-fn)))

(defn pem-seq
  "Return a lazy seq of objects from a PEMReader."
  [reader]
  (take-while
   (complement nil?)
   (repeatedly #(.readObject reader))))

(defn keystore
  "Create a blank KeyStore."
  []
  (KeyStore/getInstance (KeyStore/getDefaultType)))