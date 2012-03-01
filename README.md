# crypto-keystore

A library for managing Java keystores in Clojure, with an emphasis on
compatibility with OpenSSL.

Currently very much in development.

## Installation

Add the following dependency to your `project.clj` file:

    [crypto-keystore "0.1.0"]

## Usage

There aren't many functions yet, but you can create a blank keystore:

```clojure
(use 'crypto.keystore)

(def ks (keystore))
```

And then import certificates in OpenSSL PEM format from an I/O object like
a file:

```clojure
(import-cert ks "server" (io/file "server.crt"))
```

Or just as a raw string:

```clojure
(import-cert ks "server" (slurp "server.crt"))
```

You can also export certificates, either as a string:

```clojure
(export-cert ks "server")   ;; returns the certificate string
```

Or into an I/O object:

```clojure
(export-cert ks "server" (io/file "new-server.crt"))
```

## License

Copyright (C) 2012 James Reeves

Distributed under the Eclipse Public License, the same as Clojure.
