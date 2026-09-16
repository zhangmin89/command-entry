using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;

namespace CommandEntry.TestProbe;

internal static partial class Program
{
    private static readonly UTF8Encoding Utf8 = new(false);
    [LibraryImport("kernel32.dll")]
    private static partial nint GetConsoleWindow(); // Borrowed HWND; never close it.

    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Utf8;
        if (args is ["probe", .. var probe]) return await Probe(probe);
        throw new ArgumentException("Expected the probe command.");
    }

    private static async Task<int> Probe(string[] args)
    {
        switch (args[0])
        {
            case "gated-exit": await Console.In.ReadLineAsync(); return int.Parse(args[1]);
            case "exit": return int.Parse(args[1]);
            case "text": Console.WriteLine(args[1]); Console.Error.WriteLine(args[1]); return 0;
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
