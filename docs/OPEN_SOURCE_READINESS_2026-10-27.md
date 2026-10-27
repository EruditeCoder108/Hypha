# Public source snapshot review — 27 October 2026



This repository starts with fresh Git history and a public no-reply author identity. It is a curated source snapshot, not a fork or history-preserving merge of the private engineering repository.



Included: Android/Flutter and Rust source, the rebuilt ARM64 JNI library, experimental BLE ESP firmware, approved branding, generated README/card artwork, architecture decisions, synthetic fixtures, and selected sanitized engineering summaries.



Excluded: device databases and sidecars, chat/contact screenshots, raw device captures and logs, personal presentation work, old Git history, machine configuration/signing files, and custom-PCB/vendor-reference archives requiring separate redistribution review.



The JNI library was rebuilt from source with neutral path prefixes; its exports match all 35 Kotlin native declarations. The source-copy scan checks for the maintainer's private author email, Windows user paths, and common credential/private-key patterns. Public upstream copyright/attribution lines remain in third-party license notices.



These are bounded checks, not an exhaustive security audit. Recheck new files before future publication, use synthetic data for issues/tests, and never merge or push the private engineering repository's history into this repository.



Original Hypha works use [PolyForm Noncommercial 1.0.0](../LICENSE). This is source-available, not OSI open source; commercial use needs separate permission and there is no automatic license conversion. Third-party terms remain intact. See [the license policy](LICENSE_POLICY.md).



Continue public development from a clean clone of this repository. The older private repository must remain private.

