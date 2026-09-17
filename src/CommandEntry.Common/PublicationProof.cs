namespace CommandEntry;

internal sealed record PublicationProof(string? RequestHash, string? PolicyHash)
{
    internal const string RequestVariable = "COMMAND_ENTRY_OWNER_REQUEST_SHA256";
    internal const string PolicyVariable = "COMMAND_ENTRY_OWNER_POLICY_SHA256";

    internal void Validate()
    {
        foreach (string? hash in new[] { RequestHash, PolicyHash })
            RecordJson.Require(hash is { Length: 64 } && hash.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'), "publication_proof_required");
    }
}
