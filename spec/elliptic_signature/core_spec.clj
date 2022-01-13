(ns elliptic-signature.core-spec
  (:require [speclj.core :refer :all]
            [elliptic-signature.core :refer :all])
  (:import (java.nio.charset StandardCharsets)))

(describe "verification"
  (it "decodes chars"
    (should= 16rab (Integer/parseInt "ab" 16)))

  (it "does hex-decode"
    (should= "deadbeef"(bytes->string (hex-decode "deadbeef")))
    (should= "aff9a9f017f32b2e8b60754a4102db9d9cf9ff2b967804b50e070780aa45c9a8"
             (bytes->string (hex-decode "aff9a9f017f32b2e8b60754a4102db9d9cf9ff2b967804b50e070780aa45c9a8")))
    )

  (it "converts byte arrays to strings"
    (should= "abcdef" (bytes->string (hex-decode "abcdef"))))

  (it "xors bytes"
    (should= "b2ce" (bytes->string (xor-bytes (hex-decode "af01")
                                              (hex-decode "1dcf"))))
    (should= "000000000000"
             (bytes->string
               (xor-bytes (hex-decode "deadbeeffeed")
                          (hex-decode "deadbeeffeed"))))
    (should= "ffffffffffff"
             (bytes->string
               (xor-bytes (hex-decode "aaaacccc3333")
                          (hex-decode "55553333cccc"))))
    )

  (it "should convert numbers to bytes"
    (should= "1fcde563"
             (bytes->string
               (num->bytes 4
                           (biginteger*
                             (hex-decode "1fcde563")))))

    (should= "ffcde563"
                 (bytes->string
                   (num->bytes 4
                               (biginteger*
                                 (hex-decode "ffcde563")))))
    )

  (it "verifies"
    (should= true
             (verify
               (hex-decode "aff9a9f017f32b2e8b60754a4102db9d9cf9ff2b967804b50e070780aa45c9a8")
               (hex-decode "2a3a85a53e99af51eb6b3303fb4c902594827f4c9da0a183f743054a9e3d3a33")
               (hex-decode "0e049520f7683ab9ca1c3f50243e09c11ace8fcabb0e2fcdd80861b9802d83180ca0bed00f42a032ac780152a3b3a5c01c136a271a7d360379a1f29e13eceb9d"))
             ))

  (it "signs"
    (let [private-key-1 (sha-256 (.getBytes "my private key 1" StandardCharsets/UTF_8))
          private-key-2 (sha-256 (.getBytes "my private key 2" StandardCharsets/UTF_8))
          public-key-1 (num->bytes 32 (pub-key private-key-1))
          public-key-2 (num->bytes 32 (pub-key private-key-2))
          message-1 (sha-256 (.getBytes "my message 1" StandardCharsets/UTF_8))
          message-2 (sha-256 (.getBytes "my message 2" StandardCharsets/UTF_8))
          sig-1 (sign private-key-1 message-1)
          sig-2 (sign private-key-2 message-2)
          ]
      (should= true (verify public-key-1 message-1 sig-1))
      (should= true (verify public-key-2 message-2 sig-2))
      (should-not (verify public-key-1 message-1 sig-2))
      (should-not (verify public-key-2 message-2 sig-1))
      (should-not (verify public-key-1 message-2 sig-1))
      (should-not (verify public-key-2 message-1 sig-2))
      ))
  )


;; example:
;; (verify
;;  (hex-decode "aff9a9f017f32b2e8b60754a4102db9d9cf9ff2b967804b50e070780aa45c9a8")
;;  (hex-decode "2a3a85a53e99af51eb6b3303fb4c902594827f4c9da0a183f743054a9e3d3a33")
;;  (hex-decode "0e049520f7683ab9ca1c3f50243e09c11ace8fcabb0e2fcdd80861b9802d83180ca0bed00f42a032ac780152a3b3a5c01c136a271a7d360379a1f29e13eceb9d"))

