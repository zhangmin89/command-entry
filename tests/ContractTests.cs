using System.Text;
using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

internal static class ContractTests
{
    [Case]
    private static void CanonicalNumbersAndRequestIdentities()
    {
        var fixture = Read(Path.Combine(AppContext.BaseDirectory, "Fixtures", "reference.json"));
        Check.Equal(281, fixture["numbers"].Array().Count);
        foreach (var item in fixture["numbers"].Array())
        {
            double value = BitConverter.ToDouble(Convert.FromHexString(item!["bits"].String()));
            string expected = item["expected"].String();
            Check.Equal(expected, Utf8.GetString(Packed(JsonValue.Create(value))));
            Check.Equal(expected, Utf8.GetString(Packed(JsonNode.Parse(expected))));
        }
        Check.Equal(5, fixture["requests"].Array().Count);
        foreach (var item in fixture["requests"].Array())
        {
            var request = RequestShape.Shape(item!["business"].Object());
            Check.Json(item["expected"], request);
            Check.Equal(item["digest"].String(), RequestDigest(request));
        }
        foreach (var item in fixture["redactions"].Array())
            Check.Equal(item!["expected"].String(), OutputCapture.RedactLine(item["input"].String()));
        Check.Equal("{\"\\ue000\":2,\"\\ud83d\\ude00\":1}", Utf8.GetString(Packed(new JsonObject { ["😀"] = 1, ["\ue000"] = 2 })));
    }

    [Case]
    private static void ReadTextMatchesRecordedReference()
    {
        using var f = new Fixture();
        var cases = Read(Path.Combine(AppContext.BaseDirectory, "Fixtures", "reference.json"))["reads"].Array();
        Check.Equal(45, cases.Count);
        foreach (var item in cases)
        {
            string path = f.FilePath(item!["name"].String() + ".txt");
            File.WriteAllBytes(path, Convert.FromBase64String(item["data"].String()));
            var form = new JsonObject { ["file"] = path, ["start_line"] = item["start"]?.Copy(), ["max_lines"] = item["count"]?.Copy() };
            if (item["encoding"] is not null) form["encoding"] = item["encoding"]?.Copy();
            var actual = f.Client.Call("read_text", form);
            foreach (var field in item["expected"].Object())
                if (field.Key == "has_decode_warning") Check.Equal(field.Value.IsTrue(), actual.ContainsKey("decode_warning"));
                else Check.Json(field.Value, actual[field.Key]);
        }
    }

    [Case]
    private static void ReadTextRootsPaginationAndQuotas()
    {
        using var f = new Fixture();
        string path = f.Write("lines.txt", "a\rb\r\nc\nd\u2028e");
        var first = f.Client.Call("read_text", new JsonObject { ["file"] = path, ["max_lines"] = 2 });
        Check.Equal("a\rb\r\n", first["text"].String());
        Check.Equal(3L, first["next_start_line"].Integer("count"));
        Check.True(!first["total_lines_known"].IsTrue());
        var next = f.Client.Call("read_text", new JsonObject { ["file"] = path, ["start_line"] = 3, ["max_lines"] = 10 });
        Check.Equal("c\nd\u2028e", next["text"].String());
        Check.Equal(5L, next["total_lines"].Integer("count"));
        Check.True(next["total_lines_known"].IsTrue() && !next["remaining"].IsTrue());
        f.Policy["read_roots"] = new JsonArray(); f.Restart();
        var denied = f.Client.Raw("read_text", new JsonObject { ["file"] = path });
        Check.True(denied["isError"].IsTrue(), denied.ToJsonString());
        Check.Equal("file_outside_read_roots", JsonNode.Parse(denied["content"]![0]!["text"].String())!["reason"].String());
        f.Policy["read_roots"] = new JsonArray("@working_roots"); f.Restart();
        Check.Equal("a\rb\r\nc\nd\u2028e", f.Client.Call("read_text", new JsonObject { ["file"] = path })["text"].String());
        f.Policy["read_quota_bytes"] = 256; f.Restart();
        string longFile = f.Write("long.txt", "short\n" + new string('x', 100000) + "\nlast");
        Check.Equal("short\n", f.Client.Call("read_text", new JsonObject { ["file"] = longFile, ["max_lines"] = 1 })["text"].String());
        Check.True(f.Client.Call("read_text", new JsonObject { ["file"] = longFile, ["start_line"] = 2, ["max_lines"] = 1 }).ContainsKey("error"));
        Check.Equal("last", f.Client.Call("read_text", new JsonObject { ["file"] = longFile, ["start_line"] = 3, ["max_lines"] = 1 })["text"].String());
    }

    [Case]
    private static void SchemaAndRejectedOptionsCreateNoClaims()
    {
        using var f = new Fixture();
        var tools = f.Client.Rpc("tools/list", new())["tools"].Array();
        Check.Equal("cancel,output,read_text,start_operation,status,wait", string.Join(',', tools.Select(tool => tool!["name"].String()).Order()));
        var start = tools.Single(tool => tool!["name"].Text() == "start_operation")!;
        Check.Contains("300 seconds and 1048576 bytes", start["description"].String());
        Check.Equal(1800L, start["inputSchema"]!["properties"]!["run_seconds"]!["maximum"].Integer("maximum"));
        foreach (var (key, invalids) in new[]
        {
            ("run_seconds", new[] { "true", "null", "0", "1801", "\"30\"", "1.5" }),
            ("output_quota_bytes", new[] { "true", "null", "1023", "16777217", "\"1024\"", "2048.5" })
        })
            foreach (string raw in invalids)
            {
                var form = f.Form("location"); form[key] = JsonNode.Parse(raw);
                var result = f.Client.Raw("start_operation", form);
                Check.True(result["isError"].IsTrue(), result.ToJsonString());
                Check.Contains(key, result.ToJsonString());
            }
        Check.Equal(0, Directory.GetDirectories(f.Serve).Length);
        var request = new JsonObject { ["task_ref"] = "shape", ["step_ref"] = "read", ["operation"] = "read_text", ["cwd"] = f.DirectoryPath, ["file"] = f.PolicyPath };
        request["stdin_file"] = f.PolicyPath;
        Check.Throws<InvalidRequest>(() => RequestShape.Shape(request), "stdin_file_requires_execution_operation");
        request.Remove("stdin_file"); request["run_seconds"] = 3;
        Check.Throws<InvalidRequest>(() => RequestShape.Shape(request), "execution_options_require_execution_operation");
    }

    [Case]
    private static void NativeArgumentsStdinCwdExitAndNoConsole()
    {
        using var f = new Fixture();
        string[] args = ["", "a b", "\"quoted\"", "x\\", "&|%$()`", "中文😀", "x\\\"y"];
        string input = f.FilePath("输入 stdin.bin"); byte[] bytes = Enumerable.Range(0, 256).Select(value => (byte)value).ToArray();
        File.WriteAllBytes(input, bytes);
        var form = f.Form(["echo", .. args]); form["stdin_file"] = input;
        var state = f.Execute(form);
        Check.Equal("exited", state["state"].String()); Check.Equal(7L, state["process"]!["exit_code"].Integer("exit"));
        Check.True(!state["operation_result"]!["acceptable_exit"].IsTrue());
        var actual = JsonNode.Parse(f.Output(state["execution_id"].String())).Object();
        Check.Json(new JsonArray(args.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray()), actual["args"]);
        Check.Equal(Convert.ToBase64String(bytes), actual["stdin"].String()); Check.Equal(0L, actual["console"].Integer("window"));
        Check.Equal(f.DirectoryPath, actual["cwd"].String());
        Check.True(Read(Path.Combine(state["record_dir"].String(), "result.json"))["bindings"].Object().ContainsKey(input));
    }

    [Case]
    private static void NativeIdentityAndLocation()
    {
        using var f = new Fixture(); var form = f.Form("location"); var state = f.Execute(form);
        Check.Equal("exited", state["state"].String()); Check.Equal(0L, state["process"]!["exit_code"].Integer("exit"));
        string id = state["execution_id"].String(); var envelope = f.Envelope(id); var request = RequestShape.Shape(envelope["business"].Object());
        Check.Equal(RequestDigest(request), envelope["fingerprint"].String()); Check.Equal(Digest(form), envelope["content_fingerprint"].String());
        Check.Equal(request["request_id"].String(), state["request_id"].String());
        Check.Equal(f.DirectoryPath, JsonNode.Parse(f.Output(id))!["cwd"].String());
        var second = f.Execute(form); Check.True(second["execution_id"].String() != id);
        var location = Fixture.Run(TestRunner.Server, ["location"]);
        Check.Equal(0, location.Exit); Check.Equal(TestRunner.Root, JsonNode.Parse(location.Out)!["cwd"].String());
    }

    [Case]
    private static void OutputRedactionQuotaAndUnicodePaging()
    {
        using var f = new Fixture(); var form = f.Form("output", "100"); form["output_quota_bytes"] = 1024;
        var state = f.Execute(form); Check.Equal("exited", state["state"].String()); string id = state["execution_id"].String();
        var output = state["output"]!["stdout"]!;
        Check.True(output["capture_complete"].IsTrue() && output["redacted"].IsTrue());
        Check.True(output["retained_utf8_bytes"].Integer("bytes") <= 1024 && output["missing_lines"].Integer("lines") > 0);
        Check.True(!f.Output(id).Contains("synthetic-fixture", StringComparison.Ordinal));
        Check.Equal("中文", f.Client.Call("output", new JsonObject { ["execution_id"] = id, ["offset"] = 1, ["count"] = 2 })["text"].String());
        Check.Contains("yyy", f.Output(id, "stderr"));
        Check.Equal("once\n", File.ReadAllText(f.FilePath("writes.txt")));
    }

    [Case]
    private static void LargeOutputAndPagingDoNotExecuteTwice()
    {
        using var f = new Fixture(); var form = f.Form("output", "12000"); form["output_quota_bytes"] = 2097152; form["run_seconds"] = 1800;
        var state = f.Execute(form); Check.Equal("exited", state["state"].String()); string id = state["execution_id"].String();
        Check.Equal(1800L, state["run_budget_seconds"].Integer("budget"));
        foreach (string stream in new[] { "stdout", "stderr" })
        {
            Check.True(state["output"]![stream]!["retained_utf8_bytes"].Integer("bytes") > 1048576);
            Check.True(state["output"]![stream]!["retained_view_complete"].IsTrue());
            string retained = File.ReadAllText(Path.Combine(state["record_dir"].String(), stream + ".txt"), Utf8);
            int length = retained.EnumerateRunes().Count();
            var page = f.Client.Call("output", new JsonObject { ["execution_id"] = id, ["stream"] = stream, ["offset"] = length - 50, ["count"] = 50 });
            Check.Equal(string.Concat(retained.EnumerateRunes().Skip(length - 50)), page["text"].String()); Check.True(page["retained_view_end"].IsTrue());
        }
        string request = Path.Combine(f.Serve, id, "request.json"), policy = Path.Combine(f.Serve, id, "policy.json");
        var duplicate = Fixture.Run(TestRunner.Server, ["run", "--request", request, "--policy", policy]);
        Check.Equal(0, duplicate.Exit); Check.True(JsonNode.Parse(duplicate.Out)!["duplicate_delivery"].IsTrue());
        Check.Equal("once\n", File.ReadAllText(f.FilePath("writes.txt")));
    }

    [Case]
    private static void DefaultBudgetsAndOutputExceedOldLimit()
    {
        using var f = new Fixture(); var state = f.Execute(f.Form("output", "1500")); Check.Equal("exited", state["state"].String());
        Check.Equal(300L, state["run_budget_seconds"].Integer("budget")); Check.Equal(1048576L, state["output_quota_bytes"].Integer("quota"));
        foreach (string stream in new[] { "stdout", "stderr" })
        { Check.True(state["output"]![stream]!["retained_utf8_bytes"].Integer("bytes") > 65536); Check.True(state["output"]![stream]!["retained_view_complete"].IsTrue()); }
    }

    [Case]
    private static void TimeoutAndDuplicateOptionsKeepOneExecution()
    {
        using var f = new Fixture(); var form = f.Form("sleep", "10000"); form["run_seconds"] = 2;
        var first = f.Start(form); form["run_seconds"] = 20; form["output_quota_bytes"] = 2048;
        var second = f.Start(form); Check.Equal(first["execution_id"].String(), second["execution_id"].String()); Check.True(second["in_flight_dedup"].IsTrue());
        var state = f.Terminal(first["execution_id"].String()); Check.Equal("timed_out", state["state"].String());
        Check.Equal(2L, state["run_budget_seconds"].Integer("budget")); Check.Equal(1048576L, state["output_quota_bytes"].Integer("quota"));
        Check.True(!state["worker_observation"]!["alive"].IsTrue());
    }

    [Case]
    private static void ChangedStdinRetryAndNewContentRejection()
    {
        using var f = new Fixture(); string input = f.Write("input.txt", "first"), output = f.FilePath("out.txt");
        var form = f.Form("relay", output); form["stdin_file"] = input;
        var first = f.Execute(form); Check.Equal("exited", first["state"].String()); Check.Equal("first", File.ReadAllText(output));
        form["previous_execution"] = first["execution_id"]?.Copy();
        var rejected = f.Execute(form); Check.Equal("rejected", rejected["state"].String()); Check.Contains("verified_changed_conditions_required", rejected["error"]!["reason"].String());
        File.WriteAllText(input, "second", Utf8); form["previous_execution"] = rejected["execution_id"]?.Copy();
        var changed = f.Execute(form); Check.Equal("exited", changed["state"].String()); Check.Equal("second", File.ReadAllText(output));
        Check.True(changed["changed_conditions"].Array().Any(value => value.Text() == input));
        form["args"]!.AsArray().Add("different"); form["previous_execution"] = changed["execution_id"]?.Copy();
        var mismatched = f.Client.Raw("start_operation", form); Check.True(mismatched["isError"].IsTrue()); Check.Contains("previous_execution_content_mismatch", mismatched.ToJsonString());
    }

    [Case]
    private static void MissingStdinAndNativeInterpreterSmugglingRejected()
    {
        using var f = new Fixture(); var missing = f.Form("location"); missing["stdin_file"] = f.FilePath("absent");
        var state = f.Execute(missing); Check.Equal("rejected", state["state"].String()); Check.Equal("FileNotFoundError", state["error"]!["kind"].String());
        var smuggled = f.Form("location"); smuggled["program"] = "python";
        state = f.Execute(smuggled); Check.Equal("rejected", state["state"].String()); Check.Contains("interpreter_requires_explicit", state["error"]!["reason"].String());
    }

    [Case]
    private static void AcceptanceSeparateFromExitCode()
    {
        using var f = new Fixture(); string output = f.FilePath("artifact.json");
        foreach (int expected in new[] { 3, 2 })
        {
            var form = f.Form("artifact", output); form["artifacts"] = new JsonObject { ["result"] = output };
            form["acceptance"] = new JsonArray(new JsonObject { ["kind"] = "json_equals", ["artifact"] = "result", ["keys"] = new JsonArray("n"), ["expected"] = expected });
            var state = f.Execute(form); Check.Equal("exited", state["state"].String()); Check.True(state["operation_result"]!["acceptable_exit"].IsTrue());
            Check.Equal(expected == 2 ? "confirmed" : "not_fulfilled", state["subgoal"]!["status"].String());
            Check.Equal(expected == 2, state["subgoal"]!["evidence"]![0]!["matches"].IsTrue());
        }
    }
}
