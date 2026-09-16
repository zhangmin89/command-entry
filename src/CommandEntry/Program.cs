using System.Text.Json.Nodes;

namespace CommandEntry;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        string? ownerInput = Environment.GetEnvironmentVariable(OwnerLauncher.InputVariable);
        if (ownerInput is not null)
        {
            Environment.SetEnvironmentVariable(OwnerLauncher.InputVariable, null);
            return await ExecutionOwner.Serve(ownerInput);
        }
        try
        {
            int? maintenance = await RuntimeCommands.Run(args);
            if (maintenance is not null) return maintenance.Value;
            if (args is ["worker"]) return await ExecutionWorker.Run();
            if (args is ["location"]) { Write(ExecutionOwner.Location()); return 0; }
            if (args is ["serve", "--record-dir", var directory]) return await ExecutionOwner.Serve(directory);
            if (args is ["run", "--request", var request, "--policy", var policy])
            {
                var result = await ExecutionOwner.Run(request, policy); Write(result);
                return result["state"].Text() is "exited" or "running" or "starting" or "cancel_requested" or "cleaning" ? 0 : 125;
            }
            string? policyPath = null, bindingPath = null;
            for (int i = 0; i < args.Length; i += 2)
            {
                RecordJson.Require(i + 1 < args.Length && args[i] is "--policy" or "--binding", "expected_--policy_path_and_optional_--binding_path");
                if (args[i] == "--policy") policyPath = args[i + 1]; else bindingPath = args[i + 1];
            }
            RecordJson.Require(policyPath is not null, "--policy_required");
            await McpHost.Run(policyPath!, bindingPath);
            return 0;
        }
        catch (Exception error) when (ExecutionRecords.Handled(error))
        {
            var detail = ExecutionRecords.Error(error); detail["fatal"] = "startup_self_check_failed";
            Console.Error.WriteLine(RecordJson.Utf8.GetString(RecordJson.Packed(detail)));
            return 125;
        }
    }
    private static void Write(JsonObject value) => Console.WriteLine(RecordJson.Utf8.GetString(RecordJson.Packed(value)));
}
