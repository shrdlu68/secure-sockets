(in-package :secure-sockets)

(defparameter *default-ca-certs-location*
  (or (probe-file "/etc/ssl/certs/ca-certificates.crt")
      (probe-file "/etc/pki/tls/certs/ca-bundle.crt")
      (probe-file "/var/lib/ca-certificates/ca-bundle.pem")
      (probe-file "C:\windows\system32\curl-ca-bundle.crt")
      (probe-file "/etc/ssl/certs")
      (probe-file "C:\windows\system32\\")))

(defparameter *default-buffer-length* (- (expt 2 14) 512))

(deftype octet ()
  '(unsigned-byte 8))

(deftype octet-vector ()
  '(simple-array octet *))

(defclass secure-socket (trivial-gray-streams:fundamental-binary-input-stream
			 trivial-gray-streams:fundamental-binary-output-stream
			 trivial-gray-streams:trivial-gray-stream-mixin)
  ((cl-tls-read-cb :initarg :read-cb
		   :accessor read-cb)
   (cl-tls-write-cb :initarg :write-cb
		    :accessor write-cb)
   (cl-tls-close-cb :initarg :close-cb
		    :accessor close-cb)
   (read-buffer :initform nil)
   (write-buffer :initform (make-array *default-buffer-length* :element-type 'octet))
   (read-buffer-position :initform 0)
   (write-buffer-position :initform 0)))

(defmethod trivial-gray-streams:stream-read-byte ((ss secure-socket))
  (with-slots (cl-tls-read-cb read-buffer read-buffer-position) ss
    (handler-case
	(cond ((and read-buffer
		    (= read-buffer-position (length read-buffer)))
	       (setf read-buffer (or (funcall cl-tls-read-cb)
				     (return-from trivial-gray-streams:stream-read-byte nil)))
	       (setf read-buffer-position 1)
	       (aref read-buffer 0))
	      (t
	       (or read-buffer
		   (setf read-buffer (funcall cl-tls-read-cb)))
	       (let ((uint8 (aref read-buffer read-buffer-position)))
		 (incf read-buffer-position)
		 uint8)))
      (stream-error (err) :eof))))

(defmethod trivial-gray-streams:stream-write-byte ((ss secure-socket) uint8)
  (with-slots (cl-tls-write-cb write-buffer write-buffer-position) ss
    (cond ((= write-buffer-position (length write-buffer))
	   (funcall cl-tls-write-cb write-buffer)
	   (setf (aref write-buffer 0) uint8)
	   (setf write-buffer-position 1)
	   uint8)
	  (t
	   (setf (aref write-buffer write-buffer-position) uint8)
	   (incf write-buffer-position)
	   uint8))))

(defmethod trivial-gray-streams:stream-read-sequence ((ss secure-socket) sequence start end &key)
  (with-slots (cl-tls-read-cb read-buffer read-buffer-position) ss
    (unless start (setf start 0))
    (unless end (setf end (length sequence)))
    (let ((pos start)
	  (len (- (or end (length sequence)) start))
	  (read-buffer-len (length read-buffer)))
      ;; Read from the read buffer if there's any unread data
      (when (< read-buffer-position read-buffer-len)
	(cond ((<= len (- read-buffer-len read-buffer-position))
	       (replace sequence read-buffer
			:start1 start :end1 end
			:start2 read-buffer-position)
	       (incf read-buffer-position len)
	       (return-from trivial-gray-streams:stream-read-sequence end))
	      (t
	       (replace sequence read-buffer
			:start1 start :start2 read-buffer-position)
	       (incf pos (- read-buffer-len read-buffer-position))
	       (setf read-buffer-position read-buffer-len))))
      (loop
	 for res = (handler-case (funcall cl-tls-read-cb)
		     (stream-error (err) nil))
	 for res-len = (and res (length res))
	 for needed-len = (- end pos)
	 do
	   (if res
	       (cond ((<= res-len needed-len)
		      (replace sequence res :start1 pos)
		      (if (= needed-len res-len)
			  (return end)
			  (incf pos res-len)))
		     (t
		      (replace sequence res :start1 pos :end1 end)
		      (setf read-buffer res)
		      (setf read-buffer-position needed-len)
		      (return end)))
	       (return pos))))))

(defmethod trivial-gray-streams:stream-write-sequence ((ss secure-socket) sequence start end &key)
  (with-slots (cl-tls-write-cb write-buffer write-buffer-position) ss
    (funcall cl-tls-write-cb (subseq sequence start end))))

(defmethod trivial-gray-streams:stream-finish-output ((ss secure-socket))
  (with-slots (cl-tls-write-cb write-buffer write-buffer-position) ss
    (when (plusp write-buffer-position)
      (funcall cl-tls-write-cb (subseq write-buffer 0 write-buffer-position))
      (setf write-buffer-position 0)
      nil)))

(defmethod trivial-gray-streams:stream-force-output ((ss secure-socket))
  (with-slots (cl-tls-write-cb write-buffer write-buffer-position) ss
    (when (plusp write-buffer-position)
      (funcall cl-tls-write-cb (subseq write-buffer 0 write-buffer-position))
      (setf write-buffer-position 0)
      nil)))

(defmethod trivial-gray-streams:stream-clear-output ((ss secure-socket))
  (with-slots (write-buffer-position) ss
    (setf write-buffer-position 0)))

(defmethod cl-tls:request-stream-to-address ((addr cl-tls:address))
  (usocket:socket-stream (usocket:socket-connect
			  (cl-tls:host addr) (cl-tls:port addr)
			  :protocol :stream
			  :element-type '(unsigned-byte 8))))

(defun connect (host &key (port 443) certificate private-key
		       (ca-certificates *default-ca-certs-location*)
		       include-ciphers exclude-ciphers)
  "Connect to a server using the given options"
  (let* ((sock (usocket:socket-connect
		host port
		:protocol :stream
		:element-type '(unsigned-byte 8)))
	 (ss
	   (multiple-value-bind (read-cb write-cb close-cb)
	       (cl-tls:request-tunnel
		:certificate certificate
		:private-key private-key
		:io-stream (usocket:socket-stream sock)
		:peer-dns-name (and (stringp host) host)
		:peer-ip-addresses (and (integerp (aref host 0)) (list host))
		:exclude-ciphers exclude-ciphers
		:include-ciphers include-ciphers
		:ca-certificates (or ca-certificates
				     (error "Could not find CA certificates. Can't go on.")))
	     (make-instance 'secure-socket
			    :read-cb read-cb
			    :write-cb write-cb
			    :close-cb close-cb))))
    ss))
