using System.Text.Json.Nodes;

namespace CommandEntry;

internal sealed class ExecutionPersistenceFailure(JsonObject detail, Exception inner)
    : IOException("execution_state_persistence_failed", inner)
{
    internal JsonObject Detail { get; } = detail;
}
