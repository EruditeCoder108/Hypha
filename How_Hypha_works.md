# How Hypha works

Hypha is an Android offline messenger. Flutter renders the interface; Kotlin owns phone-radio/lifecycle/storage integration; Rust implements protocol/cryptographic surfaces exposed through JNI. Experimental ESP32 couriers use a separate C++ BLE implementation.

Verified contacts encrypt messages for the recipient. A phone or fixed courier can retain an opaque envelope and carry it to a later encounter. Accepting custody is distinct from delivery: only recipient-authenticated processing produces a delivery receipt that can return to the sender.

BLE provides current discovery and courier encounters. Wi-Fi Direct provides a separate encrypted attachment path. LoRa and phone USB attachment remain planned adapters. Relays do not receive conversation plaintext or a contact list.

Durability, forwarding allowances, expiry, pressure handling, abuse bounds, key protection and phone lifecycle behavior are separate engineering concerns. The current lost-ACK allowance defect remains open; the prototype is not a production-security claim.

Read [the roadmap](docs/HYPHA_PRODUCTION_ROADMAP.md), [threat model](THREAT_MODEL.md), [protocol invariants](PROTOCOL_INVARIANTS.md), and [architecture decisions](docs/decisions/).
