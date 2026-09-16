global using Xunit;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

// Tests change process-wide environment and observe related processes.
[assembly: Xunit.v3.Parallelization(Mode = Xunit.Sdk.ParallelMode.None)]

namespace CommandEntry.Tests;

internal static class JsonAssert
{
    internal static void Equal(JsonNode? expected, JsonNode? actual) =>
        Assert.Equal(Utf8.GetString(Packed(expected)), Utf8.GetString(Packed(actual)));
}

internal static class TestAssert
{
    internal static T Throws<T>(Action action, string message = "") where T : Exception
    {
        var error = Assert.ThrowsAny<T>(action);
        Assert.Contains(message, error.Message, StringComparison.Ordinal);
        return error;
    }
}
