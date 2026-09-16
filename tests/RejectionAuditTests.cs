using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

[Trait("Suite", "Regression")]
public sealed class RejectionAuditTests
{
    private static JsonObject Reject(Fixture fixture, string tool, JsonObject form, string reason)
    {
        var response = fixture.Client.Raw(tool, form);
        Assert.True(response["isError"].IsTrue());
        var detail = JsonNode.Parse(response["content"]![0]!["text"].String()).Object();
        Assert.Equal(reason, detail["reason"].String());
        return detail;
    }

    private static JsonObject Evidence(Fixture fixture, JsonObject detail)
    {
        var audit = detail["rejection_audit"].Object();
        string id = audit["audit_id"].String();
        Assert.True(Guid.TryParseExact(id, "D", out _));
        Assert.True(audit["recorded"]!.GetValue<bool>());
        string file = Path.Combine(fixture.DirectoryPath, "logs", "rejections", id + ".json");
        Assert.Equal(file, audit["record_file"].String());
        var record = Read(file);
        Assert.Equal(id, record["audit_id"].String());
        Assert.Equal(1L, record["schema_version"].Integer("schema"));
        Assert.Equal("rejected", record["kind"].String());
        Assert.Equal(detail["reason"].String(), record["reason"].String());
        Assert.Equal(detail["error"].String(), record["error_kind"].String());
        Assert.True(record["ts"]!.GetValue<double>() > 0);
        var logged = File.ReadLines(fixture.FilePath("logs/server-events.jsonl"))
            .Select(line => JsonNode.Parse(line).Object()).Single(item => item["audit_id"].Text() == id);
        Assert.True(logged["audit_recorded"]!.GetValue<bool>());
        JsonAssert.Equal(record["context"], logged["context"]);
        return record;
    }

    [Fact, Trait("Category", "Integration")]
    public void UnconfiguredProgramIsAuditedBeforePublication()
    {
        using var f = new Fixture();
        string script = f.Write("must-not-run.ps1", "param()\nSet-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n[IO.File]::WriteAllText('unexpected.txt', 'executed')\n");
        var form = f.Script(script); form["program"] = "pwsh";
        string policyHash = FileHash(f.PolicyPath);
        var first = Reject(f, "start_operation", form, "program_not_configured");
        Assert.Equal("Invalid", first["error"].String());
        var record = Evidence(f, first);
        Assert.Equal("start_operation", record["tool"].String());
        JsonAssert.Equal(new JsonObject { ["operation"] = "script", ["program"] = "pwsh", ["language"] = "powershell",
            ["workdir"] = f.DirectoryPath, ["script"] = script }, record["context"]);
        Assert.Empty(record["redacted_fields"].Array());
        Assert.Empty(record["truncated_fields"].Array());
        Assert.True(!record.ContainsKey("execution_id") && !first.ContainsKey("execution_id"));
        Assert.Empty(Directory.GetFileSystemEntries(f.Serve));
        Assert.True(!Directory.Exists(f.FilePath(".codex-command-records")) && !File.Exists(f.FilePath("unexpected.txt")));
        string firstFile = first["rejection_audit"]!["record_file"].String(), hash = FileHash(firstFile);
        var second = Reject(f, "start_operation", form, "program_not_configured");
        _ = Evidence(f, second);
        Assert.True(first["rejection_audit"]!["audit_id"].String() != second["rejection_audit"]!["audit_id"].String());
        Assert.Equal(2, Directory.GetFiles(f.FilePath("logs/rejections"), "*.json").Length);
        Assert.Equal(policyHash, FileHash(f.PolicyPath));
        f.Restart(); Assert.Equal(hash, FileHash(firstFile));
        string text = f.Write("still-usable.txt", "ok\n");
        Assert.Equal("ok\n", f.Client.Call("read_text", new JsonObject { ["file"] = text })["text"].String());
    }

    [Fact, Trait("Category", "Integration")]
    public void AuditOmitsPayloadAndRedactsMetadata()
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
        Assert.Equal("pwsh", record["context"]!["program"].String());
        Assert.Equal("[REDACTED credential line]\n", record["context"]!["script"].String());
        Assert.Equal("[REDACTED bearer]", record["context"]!["language"].String());
        Assert.Equal("language,script", string.Join(',', record["redacted_fields"].Array().Select(value => value.String()).Order()));
        string persisted = File.ReadAllText(detail["rejection_audit"]!["record_file"].String()) + File.ReadAllText(f.FilePath("logs/server-events.jsonl")) + detail.ToJsonString();
        foreach (string secret in new[] { "synthetic-path-secret", "synthetic-bearer-secret", "synthetic-argument-secret", "synthetic-stdin-secret", "synthetic-parameters-secret", "synthetic-artifact-secret" })
            Assert.False(persisted.Contains(secret, StringComparison.Ordinal), "Audit leaked " + secret);
        Assert.Equal(5, record["context"].Object().Count);
    }

    [Fact, Trait("Category", "Integration")]
    public void AuditBoundsUnicodeAndPrivateKeyFields()
    {
        using var f = new Fixture();
        string prefix = string.Concat(Enumerable.Repeat("😀", 1024));
        var form = f.Script("-----BEGIN PRIVATE KEY-----\nsynthetic-key-material\n-----END PRIVATE KEY-----");
        form["program"] = prefix + "x";
        var detail = Reject(f, "start_operation", form, "program_not_configured");
        var record = Evidence(f, detail);
        Assert.Equal(prefix, record["context"]!["program"].String());
        JsonAssert.Equal(new JsonArray("program"), record["truncated_fields"]);
        Assert.Equal("[REDACTED private key material]", record["context"]!["script"].String());
        JsonAssert.Equal(new JsonArray("script"), record["redacted_fields"]);
        Assert.False(File.ReadAllText(detail["rejection_audit"]!["record_file"].String()).Contains("synthetic-key-material", StringComparison.Ordinal));
    }

    [Fact, Trait("Category", "Integration")]
    public void MissingAndMalformedProgramAreAuditable()
    {
        using var f = new Fixture();
        foreach (JsonNode? program in new JsonNode?[] { null, JsonValue.Create(12), JsonValue.Create(false), new JsonArray("synthetic-array-secret"), new JsonObject { ["secret"] = "synthetic-object-secret" } })
        {
            var form = f.Form("location"); form["program"] = program?.Copy();
            var record = Evidence(f, Reject(f, "start_operation", form, "program_not_configured"));
            JsonAssert.Equal(new JsonObject { ["value_type"] = program?.GetValueKind().ToString() ?? "Null" }, record["context"]!["program"]);
            Assert.False(record.ToJsonString().Contains("synthetic-", StringComparison.Ordinal));
        }
        var absent = f.Form("location"); absent.Remove("program");
        var missing = Evidence(f, Reject(f, "start_operation", absent, "program_not_configured"));
        Assert.False(missing["context"].Object().ContainsKey("program"));
        var extra = f.Form("location"); extra["program"] = "pwsh"; extra["unknown"] = "synthetic-unknown-secret";
        var unknown = Evidence(f, Reject(f, "start_operation", extra, "unknown_form_fields"));
        Assert.Equal("pwsh", unknown["context"]!["program"].String());
        Assert.False(unknown.ToJsonString().Contains("synthetic-unknown-secret", StringComparison.Ordinal));
    }

    [Fact, Trait("Category", "Integration")]
    public void AuditWriteFailurePreservesOriginalRejection()
    {
        using var f = new Fixture();
        foreach (bool blockEntireLog in new[] { false, true })
        {
            string blocker = blockEntireLog ? f.Write("log-blocker", "preserve-log-blocker") : f.Write("logs/rejections", "preserve-audit-blocker");
            if (blockEntireLog) { f.Policy["log_root"] = blocker; f.Restart(); }
            string hash = FileHash(blocker);
            var form = f.Form("location"); form["program"] = "pwsh";
            var detail = Reject(f, "start_operation", form, "program_not_configured");
            Assert.Equal("Invalid", detail["error"].String());
            var audit = detail["rejection_audit"].Object();
            Assert.True(Guid.TryParseExact(audit["audit_id"].String(), "D", out _));
            Assert.False(audit["recorded"]!.GetValue<bool>());
            Assert.Equal("OSError", audit["storage_error"].String());
            Assert.False(audit.ContainsKey("record_file"));
            Assert.Equal(hash, FileHash(blocker));
            Assert.Empty(Directory.GetFileSystemEntries(f.Serve));
            if (!blockEntireLog)
            {
                var logged = File.ReadLines(f.FilePath("logs/server-events.jsonl")).Select(line => JsonNode.Parse(line).Object())
                    .Single(item => item["audit_id"].Text() == audit["audit_id"].String());
                Assert.False(logged["audit_recorded"]!.GetValue<bool>());
                Assert.Equal("pwsh", logged["context"]!["program"].String());
            }
        }
    }

    [Fact, Trait("Category", "Integration")]
    public void QueryRejectionsKeepTheirTargetAndWrapperUsesBusiness()
    {
        using var f = new Fixture();
        const string id = "00000000-0000-4000-8000-000000000000";
        var record = Evidence(f, Reject(f, "status", new JsonObject { ["execution_id"] = id }, "execution_not_found"));
        Assert.Equal("status", record["tool"].String());
        JsonAssert.Equal(new JsonObject { ["execution_id"] = id }, record["context"]);
        var form = f.Form("location"); form["program"] = "pwsh";
        var wrapped = new JsonObject { ["business"] = form, ["program"] = "outer-must-not-be-used" };
        var audit = Evidence(f, Reject(f, "start_operation", wrapped, "program_not_configured"));
        Assert.Equal("pwsh", audit["context"]!["program"].String());
        Assert.Empty(Directory.GetFileSystemEntries(f.Serve));
    }
}
