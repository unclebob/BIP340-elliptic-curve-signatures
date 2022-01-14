(ns elliptic-signature.core-spec
  (:require [speclj.core :refer :all]
            [elliptic-signature.core :refer :all])
  (:import (java.nio.charset StandardCharsets)))

(describe "verification"
  (it "decodes chars"
    (should= 16rab (Integer/parseInt "ab" 16)))

  (it "does hex-decode"
    (should= "deadbeef" (bytes->hex-string (hex-string->bytes "deadbeef")))
    (should= "aff9a9f017f32b2e8b60754a4102db9d9cf9ff2b967804b50e070780aa45c9a8"
             (bytes->hex-string (hex-string->bytes "aff9a9f017f32b2e8b60754a4102db9d9cf9ff2b967804b50e070780aa45c9a8")))
    )

  (it "converts byte arrays to strings"
    (should= "abcdef" (bytes->hex-string (hex-string->bytes "abcdef"))))

  (it "xors bytes"
    (should= "b2ce" (bytes->hex-string (xor-bytes (hex-string->bytes "af01")
                                                  (hex-string->bytes "1dcf"))))
    (should= "000000000000"
             (bytes->hex-string
               (xor-bytes (hex-string->bytes "deadbeeffeed")
                          (hex-string->bytes "deadbeeffeed"))))
    (should= "ffffffffffff"
             (bytes->hex-string
               (xor-bytes (hex-string->bytes "aaaacccc3333")
                          (hex-string->bytes "55553333cccc"))))
    )

  (it "should convert numbers to bytes"
    (should= "1fcde563"
             (bytes->hex-string
               (num->bytes 4
                           (bytes->num
                             (hex-string->bytes "1fcde563")))))

    (should= "ffcde563"
             (bytes->hex-string
               (num->bytes 4
                           (bytes->num
                             (hex-string->bytes "ffcde563")))))
    )

  (it "verifies Aaron Dixon's example."
    (should= true
             (verify
               (hex-string->bytes "aff9a9f017f32b2e8b60754a4102db9d9cf9ff2b967804b50e070780aa45c9a8")
               (hex-string->bytes "2a3a85a53e99af51eb6b3303fb4c902594827f4c9da0a183f743054a9e3d3a33")
               (hex-string->bytes "0e049520f7683ab9ca1c3f50243e09c11ace8fcabb0e2fcdd80861b9802d83180ca0bed00f42a032ac780152a3b3a5c01c136a271a7d360379a1f29e13eceb9d"))))

  (it "signs"
    (let [private-key-1 (sha-256 (.getBytes "my private key 1" StandardCharsets/UTF_8))
          private-key-2 (sha-256 (.getBytes "my private key 2" StandardCharsets/UTF_8))
          public-key-1 (pub-key private-key-1)
          public-key-2 (pub-key private-key-2)
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
      (should-not (verify public-key-2 message-1 sig-2)))))
