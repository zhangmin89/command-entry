using System.Runtime.ExceptionServices;
using System.Text.Json.Nodes;

namespace CommandEntry;

internal static class ExecutionCleanup
{
    internal static async Task Complete(Func<Task> execute, Func<Exception, Task> fail, Action persist)
    {
        try { await execute(); }
        catch (Exception error) when (ExecutionRecords.Handled(error))
        {
            await fail(error);
            return;
        }
        // A final write failure must not be reclassified as a business failure.
        persist();
    }

    internal static async Task PersistFailure(JsonObject result, Func<Task> cleanup, Action persist)
    {
        Exception? cleanupFailure = null;
        try { await cleanup(); }
        catch (Exception error)
        {
            cleanupFailure = error;
            result["cleanup_error"] = ExecutionRecords.Error(error);
        }
        try { persist(); }
        catch (Exception error)
        {
            var detail = new JsonObject
            {
                ["kind"] = "OSError", ["reason"] = "execution_state_persistence_failed",
                ["primary_error"] = result["error"]?.Copy(),
                ["cleanup_error"] = result["cleanup_error"]?.Copy(),
                ["persistence_error"] = ExecutionRecords.Error(error)
            };
            throw new ExecutionPersistenceFailure(detail, cleanupFailure is null ? error : new AggregateException(cleanupFailure, error));
        }
        if (cleanupFailure is not null && !ExecutionRecords.Handled(cleanupFailure))
            ExceptionDispatchInfo.Capture(cleanupFailure).Throw();
    }
}
