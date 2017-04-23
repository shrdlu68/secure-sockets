(defpackage :secure-sockets
  (:use :cl)
  (:documentation "Secure-sockets uses usocket, bordeaux-therads, trivial-gray-streams, and cl-tls to provide a simple API for socket communication"))

(in-package :secure-sockets)

(export '(connect *default-buffer-length* *default-ca-certs-location*))
