using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

internal static class RejectionAuditTests
{
    private static JsonObject Reject(Fixture fixture, string tool, JsonObject form, string reason)
    {
        var response = fixture.Client.Raw(tool, form);
        Check.True(response["isError"].IsTrue());
        var detail = JsonNode.Parse(response["content"]![0]!["text"].String()).Object();
        Check.Equal(reason, detail["reason"].String());
        return detail;
    }

    private static JsonObject Evidence(Fixture fixture, JsonObject detail)
    {
        var audit = detail["rejection_audit"].Object();
        string id = audit["audit_id"].String();
        Check.True(Guid.TryParseExact(id, "D", out _));
        Check.Equal(true, audit["recorded"]!.GetValue<bool>());
        string file = Path.Combine(fixture.DirectoryPath, "logs", "rejections", id + ".json");
        Check.Equal(file, audit["record_file"].String());
        var record = Read(file);
        Check.Equal(id, record["audit_id"].String());
        Check.Equal(1L, record["schema_version"].Integer("schema"));
        Check.Equal("rejected", record["kind"].String());
        Check.Equal(detail["reason"].String(), record["reason"].String());
        Check.Equal(detail["error"].String(), record["error_kind"].String());
        Check.True(record["ts"]!.GetValue<double>() > 0);
        var logged = File.ReadLines(fixture.FilePath("logs/server-events.jsonl"))
            .Select(line => JsonNode.Parse(line).Object()).Single(item => item["audit_id"].Text() == id);
        Check.Equal(true, logged["audit_recorded"]!.GetValue<bool>());
        Check.Json(record["context"], logged["context"]);
        return record;
    }

    [Case]
    private static void UnconfiguredProgramIsAuditedBeforePublication()
    {
        using var f = new Fixture();
        string script = f.Write("must-not-run.ps1", "param()\nSet-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n[IO.File]::WriteAllText('unexpected.txt', 'executed')\n");
        var form = f.Script(script); form["program"] = "pwsh";
        string policyHash = FileHash(f.PolicyPath);
        var first = Reject(f, "start_operation", form, "program_not_configured");
        Check.Equal("Invalid", first["error"].String());
        var record = Evidence(f, first);
        Check.Equal("start_operation", record["tool"].String());
        Check.Json(new JsonObject { ["operation"] = "script", ["program"] = "pwsh", ["language"] = "powershell",
            ["workdir"] = f.DirectoryPath, ["script"] = script }, record["context"]);
        Check.Equal(0, record["redacted_fields"].Array().Count);
        Check.Equal(0, record["truncated_fields"].Array().Count);
        Check.True(!record.ContainsKey("execution_id") && !first.ContainsKey("execution_id"));
        Check.Equal(0, Directory.GetFileSystemEntries(f.Serve).Length);
        Check.True(!Directory.Exists(f.FilePath(".codex-command-records")) && !File.Exists(f.FilePath("unexpected.txt")));
        string firstFile = first["rejection_audit"]!["record_file"].String(), hash = FileHash(firstFile);
        var second = Reject(f, "start_operation", form, "program_not_configured");
        _ = Evidence(f, second);
        Check.True(first["rejection_audit"]!["audit_id"].String() != second["rejection_audit"]!["audit_id"].String());
        Check.Equal(2, Directory.GetFiles(f.FilePath("logs/rejections"), "*.json").Length);
        Check.Equal(policyHash, FileHash(f.PolicyPath));
        f.Restart(); Check.Equal(hash, FileHash(firstFile));
        string text = f.Write("still-usable.txt", "ok\n");
        Check.Equal("ok\n", f.Client.Call("read_text", new JsonObject { ["file"] = text })["text"].String());
    }

    [Case]
    private static void AuditOmitsPayloadAndRedactsMetadata()
    {
        using var f = new Fixture();
        var form = f.Script(f.FilePath("password=synthetic-path-secret.ps1"));
        form["program"] = "pwsh"; form["language"] = "Bearer synthetic-bearer-secret";
        form["args"] = new JsonArray("synthetic-argument-secret");
        form["stdin_file"] = "synthetic-stdin-secret";
        form["parameters_file"] = "synthetic-parameters-secret";
        form["artifacts"] = new JsonObject { ["private"] = "synthetic-artifact-secret" };
        var detail = Reject(f, "start_operation", form, "program_not_configured");
        var record = Evidence(f, detail);
        Check.Equal("pwsh", record["context"]!["program"].String());
        Check.Equal("[REDACTED credential line]\n", record["context"]!["script"].String());
        Check.Equal("[REDACTED bearer]", record["context"]!["language"].String());
        Check.Equal("language,script", string.Join(',', record["redacted_fields"].Array().Select(value => value.String()).Order()));
        string persisted = File.ReadAllText(detail["rejection_audit"]!["record_file"].String()) + File.ReadAllText(f.FilePath("logs/server-events.jsonl")) + detail.ToJsonString();
        foreach (string secret in new[] { "synthetic-path-secret", "synthetic-bearer-secret", "synthetic-argument-secret", "synthetic-stdin-secret", "synthetic-parameters-secret", "synthetic-artifact-secret" })
            Check.True(!persisted.Contains(secret, StringComparison.Ordinal), "Audit leaked " + secret);
        Check.Equal(5, record["context"].Object().Count);
    }

    [Case]
    private static void AuditBoundsUnicodeAndPrivateKeyFields()
    {
        using var f = new Fixture();
        string prefix = string.Concat(Enumerable.Repeat("😀", 1024));
        var form = f.Script("-----BEGIN PRIVATE KEY-----\nsynthetic-key-material\n-----END PRIVATE KEY-----");
        form["program"] = prefix + "x";
        var detail = Reject(f, "start_operation", form, "program_not_configured");
        var record = Evidence(f, detail);
        Check.Equal(prefix, record["context"]!["program"].String());
        Check.Json(new JsonArray("program"), record["truncated_fields"]);
        Check.Equal("[REDACTED private key material]", record["context"]!["script"].String());
        Check.Json(new JsonArray("script"), record["redacted_fields"]);
        Check.True(!File.ReadAllText(detail["rejection_audit"]!["record_file"].String()).Contains("synthetic-key-material", StringComparison.Ordinal));
    }

    [Case]
    private static void MissingAndMalformedProgramAreAuditable()
    {
        using var f = new Fixture();
        foreach (JsonNode? program in new JsonNode?[] { null, JsonValue.Create(12), JsonValue.Create(false), new JsonArray("synthetic-array-secret"), new JsonObject { ["secret"] = "synthetic-object-secret" } })
        {
            var form = f.Form("location"); form["program"] = program?.Copy();
            var record = Evidence(f, Reject(f, "start_operation", form, "program_not_configured"));
            Check.Json(new JsonObject { ["value_type"] = program?.GetValueKind().ToString() ?? "Null" }, record["context"]!["program"]);
            Check.True(!record.ToJsonString().Contains("synthetic-", StringComparison.Ordinal));
        }
        var absent = f.Form("location"); absent.Remove("program");
        var missing = Evidence(f, Reject(f, "start_operation", absent, "program_not_configured"));
        Check.True(!missing["context"].Object().ContainsKey("program"));
        var extra = f.Form("location"); extra["program"] = "pwsh"; extra["unknown"] = "synthetic-unknown-secret";
        var unknown = Evidence(f, Reject(f, "start_operation", extra, "unknown_form_fields"));
        Check.Equal("pwsh", unknown["context"]!["program"].String());
        Check.True(!unknown.ToJsonString().Contains("synthetic-unknown-secret", StringComparison.Ordinal));
    }

    [Case]
    private static void AuditWriteFailurePreservesOriginalRejection()
    {
        using var f = new Fixture();
        foreach (bool blockEntireLog in new[] { false, true })
        {
            string blocker = blockEntireLog ? f.Write("log-blocker", "preserve-log-blocker") : f.Write("logs/rejections", "preserve-audit-blocker");
            if (blockEntireLog) { f.Policy["log_root"] = blocker; f.Restart(); }
            string hash = FileHash(blocker);
            var form = f.Form("location"); form["program"] = "pwsh";
            var detail = Reject(f, "start_operation", form, "program_not_configured");
            Check.Equal("Invalid", detail["error"].String());
            var audit = detail["rejection_audit"].Object();
            Check.True(Guid.TryParseExact(audit["audit_id"].String(), "D", out _));
            Check.Equal(false, audit["recorded"]!.GetValue<bool>());
            Check.Equal("OSError", audit["storage_error"].String());
            Check.True(!audit.ContainsKey("record_file"));
            Check.Equal(hash, FileHash(blocker));
            Check.Equal(0, Directory.GetFileSystemEntries(f.Serve).Length);
            if (!blockEntireLog)
            {
                var logged = File.ReadLines(f.FilePath("logs/server-events.jsonl")).Select(line => JsonNode.Parse(line).Object())
                    .Single(item => item["audit_id"].Text() == audit["audit_id"].String());
                Check.Equal(false, logged["audit_recorded"]!.GetValue<bool>());
                Check.Equal("pwsh", logged["context"]!["program"].String());
            }
        }
    }

    [Case]
    private static void QueryRejectionsKeepTheirTargetAndWrapperUsesBusiness()
    {
        using var f = new Fixture();
        const string id = "00000000-0000-4000-8000-000000000000";
        var record = Evidence(f, Reject(f, "status", new JsonObject { ["execution_id"] = id }, "execution_not_found"));
        Check.Equal("status", record["tool"].String());
        Check.Json(new JsonObject { ["execution_id"] = id }, record["context"]);
        var form = f.Form("location"); form["program"] = "pwsh";
        var wrapped = new JsonObject { ["business"] = form, ["program"] = "outer-must-not-be-used" };
        var audit = Evidence(f, Reject(f, "start_operation", wrapped, "program_not_configured"));
        Check.Equal("pwsh", audit["context"]!["program"].String());
        Check.Equal(0, Directory.GetFileSystemEntries(f.Serve).Length);
    }
}
