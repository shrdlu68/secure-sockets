;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-

(asdf:defsystem secure-sockets
  :name "secure-sockets"
  :version nil
  :author "Brian Kamotho"
  :license "BSD-3-Clause"
  :description "A higher-level API to cl-tls"

  :depends-on ("usocket" "bordeaux-threads"
			 "trivial-gray-streams" "cl-tls")
  :serial t
  :components ((:static-file "README")
	       (:static-file "LICENSE")
	       (:module "src"
		:components
			((:file "package")
			 (:file "simple-client")))))
