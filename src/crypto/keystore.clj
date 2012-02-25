(ns crypto.keystore
  "Functions for creating and managing Java Keystores."
  (:import java.security.KeyStore))

(defn keystore
  "Create a blank KeyStore."
  []
  (KeyStore/getInstance (KeyStore/getDefaultType)))