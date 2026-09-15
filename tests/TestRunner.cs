using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

[AttributeUsage(AttributeTargets.Method)]
internal sealed class CaseAttribute : Attribute;

internal static class Check
{
    internal static void True(bool value, string message = "Expected true")
    { if (!value) throw new Exception(message); }
    internal static void Equal<T>(T expected, T actual)
    { if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new Exception($"Expected <{expected}>, actual <{actual}>"); }
    internal static void Json(JsonNode? expected, JsonNode? actual) => Equal(Utf8.GetString(Packed(expected)), Utf8.GetString(Packed(actual)));
    internal static void Contains(string expected, string actual) => True(actual.Contains(expected, StringComparison.Ordinal), $"Missing <{expected}> in <{actual}>");
    internal static T Throws<T>(Action action, string message = "") where T : Exception
    {
        try { action(); }
        catch (T error) { Contains(message, error.Message); return error; }
        throw new Exception("Expected exception " + typeof(T).Name);
    }
}

internal static partial class TestRunner
{
    internal static string Root = "";
    internal static string Server = "";
    internal static string ProbeExe => Path.Combine(AppContext.BaseDirectory, "CommandEntry.Tests.exe");
    [LibraryImport("kernel32.dll")]
    private static partial nint GetConsoleWindow(); // Borrowed HWND; never close it.

    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Utf8;
        if (args is ["probe", .. var probe]) return await Probe(probe);
        var options = RuntimeCommands.Options(args, "--root", "--server", "--aot");
        Root = Path.GetFullPath(options.Required("--root"));
        Server = Path.GetFullPath(options.Required("--server"));
        Check.True(File.Exists(Server), "Build the server before running tests: " + Server);
        if (options.GetValueOrDefault("--aot") == "true") _ = RuntimeCommands.InspectAot(Server);
        var cases = Assembly.GetExecutingAssembly().GetTypes().SelectMany(type => type.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
            .Where(method => method.IsDefined(typeof(CaseAttribute))).OrderBy(method => method.DeclaringType!.Name).ThenBy(method => method.Name).ToArray();
        Check.True(cases.Length > 0, "No tests discovered");
        int passed = 0;
        foreach (var method in cases)
        {
            string name = method.DeclaringType!.Name + "." + method.Name;
            var timer = Stopwatch.StartNew();
            try
            {
                if (method.Invoke(null, null) is Task task) await task;
                passed++;
                Console.WriteLine($"PASS {name} ({timer.Elapsed.TotalSeconds:F2}s)");
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"FAIL {name}: {(error is TargetInvocationException ? error.InnerException : error)}");
                Console.WriteLine($"RESULT passed={passed} failed=1 remaining={cases.Length - passed - 1} total={cases.Length}");
                return 1;
            }
        }
        Console.WriteLine($"RESULT passed={passed} failed=0 total={cases.Length}");
        return 0;
    }

    private static async Task<int> Probe(string[] args)
    {
        switch (args[0])
        {
            case "echo":
                using (var input = new MemoryStream())
                {
                    await Console.OpenStandardInput().CopyToAsync(input);
                    Console.WriteLine(new JsonObject
                    {
                        ["args"] = new JsonArray(args[1..].Select(value => (JsonNode?)JsonValue.Create(value)).ToArray()),
                        ["stdin"] = Convert.ToBase64String(input.ToArray()), ["console"] = GetConsoleWindow().ToInt64(),
                        ["cwd"] = Environment.CurrentDirectory
                    }.ToJsonString());
                }
                return 7;
            case "sleep": await Task.Delay(int.Parse(args[1])); Console.WriteLine("survived"); return 0;
            case "output":
                File.AppendAllText("writes.txt", "once\n", Utf8);
                for (int i = 0; i < int.Parse(args[1]); i++)
                {
                    Console.Write("😀中文\npassword=synthetic-fixture\n" + new string('x', 100) + "\n");
                    Console.Error.Write(new string('y', 100) + "\n");
                }
                return 0;
            case "artifact": File.WriteAllText(args[1], "{\"n\":2}", Utf8); return 0;
            case "relay":
                using (var output = File.Create(args[1])) await Console.OpenStandardInput().CopyToAsync(output);
                return 0;
            case "location": Console.WriteLine(new JsonObject { ["cwd"] = Environment.CurrentDirectory }.ToJsonString()); return 0;
            default: throw new Exception("Unknown test probe");
        }
    }
}
