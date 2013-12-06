(ns crypto.keystore
  "Functions for creating and managing Java Keystores."
  (:require [clojure.java.io :as io])
  (:import java.io.StringReader
           java.io.StringWriter
           java.security.KeyStore
           java.security.KeyStore$PrivateKeyEntry
           java.security.KeyStore$SecretKeyEntry
           java.security.KeyStore$TrustedCertificateEntry
           java.security.KeyPair
           java.security.PrivateKey
           java.security.Security
           java.security.cert.Certificate
           org.bouncycastle.openssl.PEMReader
           org.bouncycastle.openssl.PEMWriter
           org.bouncycastle.openssl.PasswordFinder
           org.bouncycastle.jce.provider.BouncyCastleProvider))

(Security/addProvider (BouncyCastleProvider.))

(deftype PasswordFn [password-fn]
  PasswordFinder
  (getPassword [_]
    (.toCharArray (password-fn))))

(defprotocol PemSource
  (make-pem-reader [source pass-fn]))

(extend-protocol PemSource
  String
  (make-pem-reader [s pass-fn] (make-pem-reader (StringReader. s) pass-fn))
  java.io.Reader
  (make-pem-reader [r pass-fn] (PEMReader. r (PasswordFn. pass-fn)))
  Object
  (make-pem-reader [x pass-fn] (make-pem-reader (io/reader x) pass-fn)))

(defn pem-reader
  "Create a PEMReader from a PEM source and optional password function."
  ([source]
     (make-pem-reader source (constantly nil)))
  ([source password-fn]
     (make-pem-reader source password-fn)))

(defn pem-seq
  "Return a lazy seq of objects from a PEMReader."
  [reader]
  (take-while
   (complement nil?)
   (repeatedly #(.readObject reader))))

(defn import-cert
  "Import a PEM certificate file into the keystore."
  [keystore alias cert]
  (with-open [r (pem-reader cert)]
    (doseq [c (pem-seq r) :when (instance? Certificate c)]
      (.setCertificateEntry keystore alias c))))

(defn pem-writer
  "Create a PEMWriter for an output stream, reader or file."
  [output]
  (PEMWriter. (io/writer output)))

(defn- write-str [f]
  (let [sw (StringWriter.)]
    (f sw)
    (.toString sw)))

(defn load-entry [ks alias]
  "Loads the entry that belongs to specified alias in given keystore."
  {:alias alias
   :creation-date (.getCreationDate ks alias)
   :certificate-chain (seq (.getCertificateChain ks alias))
   :certificate (.getCertificate ks alias)})

(defn aliases [ks]
  "Return seq of keystore aliases."
  (enumeration-seq (.aliases ks)))

(defn load-entries [ks]
  "Loads all entries from given keystore"
  (let [store {:type (.getType ks), :provider (.getName (.getProvider ks))}
        entries (reduce conj '[] (map #(load-entry ks %) (aliases ks)))]
    (assoc store :entries entries)))


(defn certificate [ks the-alias]
  "Returns the certificate belongs to specified alias in keystore"
  (let [entries (:entries (load-entries ks))
        entry (first (filter #(= (:alias %) the-alias) entries))
        {:keys [alias certificate]} entry]
    certificate))

(defn export-cert
  "Export a certificate in a keystore encoded in PEM format. If an output is supplied,
  write to it directly, otherwise return a string."
  ([keystore alias]
     (write-str (partial export-cert keystore alias)))
  ([keystore alias output]
     (let [cert (certificate keystore alias)]
       (with-open [w (pem-writer output)]
         (.writeObject w (certificate keystore alias)))
       cert)))

(defn keystore
  "Loads a KeyStore with given parameters."
  ([] (keystore (KeyStore/getDefaultType) nil nil))
  ([type] (keystore type nil nil))
  ([type file password]
     (let [ks (KeyStore/getInstance (if (nil? type) (KeyStore/getDefaultType) type))]
       (if (nil? file)
         (doto ks (.load nil))
         (doto ks (.load (io/input-stream file) (.toCharArray password)))))))
