using System.Text.Json.Nodes;

namespace CommandEntry;

internal static class ExecutionCleanup
{
    internal static async Task PersistFailure(JsonObject result, Func<Task> cleanup, Action persist)
    {
        try { await cleanup(); }
        catch (Exception error) when (ExecutionRecords.Handled(error))
        {
            // Keep the primary failure and leave the exit status unconfirmed.
            result["cleanup_error"] = ExecutionRecords.Error(error);
        }
        finally { persist(); }
    }
}
