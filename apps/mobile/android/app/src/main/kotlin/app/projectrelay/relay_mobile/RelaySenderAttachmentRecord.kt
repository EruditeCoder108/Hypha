package app.projectrelay.relay_mobile

/** Builds recipient-private and courier-visible records from already durable direct chunks. */
internal object RelaySenderAttachmentPreparation {
    data class Prepared(
        val plan: RelayCourierAttachmentPlan,
        val recipientManifest: RelayRecipientAttachmentManifest,
    )

    fun prepare(
        attachment: RelayAttachmentManifest,
        cancellationSecret: ByteArray,
    ): Prepared {
        attachment.validate()
        require(cancellationSecret.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Attachment cancellation secret is invalid."
        }
        val plan = RelayCourierAttachmentPlan(
            objectId = attachment.attachmentId.copyOf(),
            cancellationCommitment = RelayCourierAttachmentPlan.digest(cancellationSecret),
            totalCiphertextBytes = attachment.chunks.sumOf { it.ciphertextBytes.toLong() },
            chunks = attachment.chunks.map { chunk ->
                RelayCourierAttachmentPlan.ChunkDescriptor(
                    ciphertextBytes = chunk.ciphertextBytes,
                    ciphertextSha256 = chunk.ciphertextSha256.copyOf(),
                )
            },
        ).also(RelayCourierAttachmentPlan::validate)
        val recipientManifest = RelayRecipientAttachmentManifest(
            objectId = attachment.attachmentId.copyOf(),
            kind = attachment.kind,
            courierPlanSha256 = plan.sha256(),
            contentKey = attachment.contentKey.copyOf(),
            plaintextBytes = attachment.plaintextBytes,
            plaintextSha256 = attachment.plaintextSha256.copyOf(),
            mimeType = attachment.mimeType,
            fileName = attachment.fileName,
        ).also(RelayRecipientAttachmentManifest::validate)
        return Prepared(plan, recipientManifest)
    }
}
