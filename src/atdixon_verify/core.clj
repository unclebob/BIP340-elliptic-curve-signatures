(ns atdixon-verify.core
  (:import (java.util Arrays)
           (java.security MessageDigest)
           (java.nio.charset StandardCharsets)
           ))

(defrecord Point [^BigInteger x ^BigInteger y])

(def infinity (->Point nil nil))

(def ^BigInteger zero BigInteger/ZERO)
(def ^BigInteger one BigInteger/ONE)
(def ^BigInteger two (BigInteger/valueOf 2))
(def ^BigInteger three (BigInteger/valueOf 3))
(def ^BigInteger four (BigInteger/valueOf 4))
(def ^BigInteger seven (BigInteger/valueOf 7))

(def ^BigInteger p
  (biginteger 16rFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F))
(def ^BigInteger n
  (biginteger 16rFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141))
(def ^BigInteger e
  (.divide (.add p one) four))

(def G
  (->Point
    (biginteger 16r79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
    (biginteger 16r483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)))

(defn- infinite?
  [p]
  (or (nil? (:x p)) (nil? (:y p))))

(defn add
  [p1 p2]
  (let [^BigInteger x1 (:x p1)
        ^BigInteger y1 (:y p1)
        ^BigInteger x2 (:x p2)
        ^BigInteger y2 (:y p2)
        infinite-p1? (infinite? p1)
        infinite-p2? (infinite? p2)]
    (cond
      (and infinite-p1? infinite-p2?) infinity
      infinite-p1? p2
      infinite-p2? p1
      (and (= x1 x2) (not= y1 y2)) infinity
      :else
      (let [lam (if (and (= x1 x2) (= y1 y2))
                  (.mod
                    (.multiply (.multiply (.multiply three x1) x1)
                               (.modPow (.multiply y2 two) (.subtract p two) p))
                    p)
                  (.mod
                    (.multiply (.subtract y2 y1)
                               (.modPow (.subtract x2 x1) (.subtract p two) p))
                    p))
            x3 (.mod (.subtract (.subtract (.multiply lam lam) x1) x2) p)]
        (->Point x3 (.mod (.subtract (.multiply lam (.subtract x1 x3)) y1) p))))))

(defn mul
  [p ^BigInteger n]
  (loop [i 0 R infinity P p]
    (if (= i 256)
      R
      (recur
        (inc i)
        (if (pos? (.compareTo (.and (.shiftRight n i) one) zero))
          (add R P) R)
        (add P P)))))

(defn sha-256
  ^bytes [^bytes input]
  (let [digest (MessageDigest/getInstance "SHA-256")]
    (.digest digest input)))

(def ^bytes challenge-tag-hash
  (sha-256 (.getBytes "BIP0340/challenge" StandardCharsets/UTF_8)))

(def ^bytes aux-tag-hash
  (sha-256 (.getBytes "BIP0340/aux" StandardCharsets/UTF_8)))

(def ^bytes nonce-tag-hash
  (sha-256 (.getBytes "BIP0340/nonce" StandardCharsets/UTF_8)))

(defn num->bytes [length n]
  (let [a (.toByteArray (biginteger n))
        l (count a)
        zeros (repeat (- length l) (byte 0))]
    (if (> l length)
      (byte-array (drop (- l length) (seq a)))
      (byte-array (concat zeros a)))))

(defn biginteger*
  ^BigInteger [^bytes b]
  (BigInteger. 1 b))

(defn- lift-x
  [^BigInteger x]
  (when (and (not (neg? (.signum x))) (neg? (.compareTo x p)))
    (let [^BigInteger c (.mod (.add (.modPow x three p) seven) p)
          ^BigInteger y (.modPow c e p)]
      (when (zero? (.compareTo c (.modPow y two p)))
        (->Point x (if (zero? (.signum (.and y one))) y (.subtract p y)))))))

(defn- ||
  ^bytes [& byte-arrays]
  (let [tuples (mapv vector
                     (concat byte-arrays [nil])
                     (reductions #(+ %1 (alength ^bytes %2)) 0 byte-arrays))
        rv (byte-array (second (peek tuples)))]
    (doseq [[arr offset] (butlast tuples)]
      (System/arraycopy arr 0 rv offset (alength ^bytes arr)))
    rv))

(defn bytes->string [byte-array]
  (let [byte-seq (for [i (range (alength byte-array))] (aget byte-array i))
        byte-strings (map #(apply str (take-last 2 (format "%02x" %))) byte-seq)]
    (apply str (apply concat byte-strings))))

(defn ^bytes hex-decode [s]
  (let [byte-strings (map #(apply str %) (partition 2 s))
        byte-vector (map #(Integer/parseInt % 16) byte-strings)]
    (byte-array byte-vector)))

(defn has-even-y [point]
  (= 0 (mod (:y point) 2))
  )

(defn xor-bytes [^bytes a ^bytes b]
  (assert (= (alength a) (alength b)) "byte-wise-xor: arguments not same size.")
  (let [result (byte-array (alength a))]
    (doseq [i (range (alength a))]
      (aset result i (byte (bit-xor (aget a i) (aget b i)))))
    result))

(defn pub-key [private-key]
  (:x (mul G (biginteger* private-key))))

(defn sign [^bytes private-key ^bytes message]
  (let [d- (biginteger* private-key)
        P (mul G d-)
        d (if (has-even-y P) d- (- n d-))
        t (xor-bytes (num->bytes 32 d) aux-tag-hash)
        rnd (sha-256 (|| nonce-tag-hash nonce-tag-hash
                         t
                         (num->bytes 32 (:x P))
                         message))
        k- (.mod (biginteger* rnd) n)
        R (mul G k-)
        k (if (has-even-y R) k- (- n k-))
        e (.mod
            (biginteger* (sha-256 (|| challenge-tag-hash challenge-tag-hash
                                      (num->bytes 32 (:x R))
                                      (num->bytes 32 (:x P))
                                      message)))
            n)
        sig (|| (num->bytes 32 (:x R))
                (num->bytes 32 (mod (+ k (* e d)) n)))
        ]
    sig))



(defn verify
  ;; @see https://bips.xyz/340#verification
  [^bytes public-key ^bytes message ^bytes signature]
  (when (and
          (= 32 (alength ^bytes public-key) (alength ^bytes message))
          (= 64 (alength ^bytes signature)))
    (when-let [P (lift-x (biginteger* public-key))]
      (let [r-bytes (Arrays/copyOfRange signature 0 32)
            r (biginteger* r-bytes)
            s (biginteger* (Arrays/copyOfRange signature 32 64))]
        (when (and
                (< (.compareTo r p) 0)
                (< (.compareTo s n) 0))
          (let [e (.mod
                    (biginteger*
                      (sha-256
                        (|| challenge-tag-hash challenge-tag-hash r-bytes public-key message))) n)
                R (add (mul G s) (mul P (.subtract n e)))]
            (when
              (and
                (not= R infinity)
                (zero? (.compareTo (.mod ^BigInteger (:y P) two) zero))
                (zero? (.compareTo ^BigInteger (:x R) r)))
              true)))))))


