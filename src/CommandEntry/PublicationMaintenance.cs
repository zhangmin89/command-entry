using System.Diagnostics;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

// One-time, explicitly invoked maintenance for the three reviewed half-publications.
// Preview is read-only. Records are moved intact and never deleted.
internal static class PublicationMaintenance
{
    internal static readonly (string Id, string Fingerprint)[] Identities =
    [
        ("32ee416c-7ed3-532e-856c-3ff84f09a257", "da09a52adc587ee5b30ade57750bb9dcf12075e9ed7c188955db5d265705766c"),
        ("b6e13d59-0a85-5f3b-be87-3c4d22743647", "d060a957baea03c74fec260aa905813b6a23cdede4318e4ceaf66e1ba0a28ace"),
        ("0b25593f-66dc-5deb-84f7-745e23a40692", "c0e95ed5888ac9bac76d9fc69dda3f37d3ca3f544cc4473241208d5512db19a8")
    ];

    private static string Checked(string path, string kind)
    {
        string result = BusinessPaths.Resolve(path, kind);
        Require((File.GetAttributes(result) & FileAttributes.ReparsePoint) == 0, "Reparse-point paths are not supported: " + result);
        return result;
    }
    private static string CheckedHash(string path) => FileHash(Checked(path, "file"));
    private static JsonObject AssertBinding(string root)
    {
        string policy = Path.Combine(root, "policy.json"); var binding = Read(Path.Combine(root, "binding.json"));
        Require(binding.Int("schema_version", 0) == 2 && Path.GetFullPath(binding["policy"]!["path"].String()).Equals(policy, StringComparison.OrdinalIgnoreCase)
            && CheckedHash(policy) == binding["policy"]!["sha256"].Text(), "Installed policy does not match its reviewed binding.");
        foreach (var item in binding["runtime_files"].Array())
        {
            string path = Path.GetFullPath(item!["path"].String());
            Require(Path.GetDirectoryName(path)!.Equals(root, StringComparison.OrdinalIgnoreCase) && CheckedHash(path) == item["sha256"].Text(),
                "Installed runtime does not match its reviewed binding: " + path);
        }
        return binding;
    }

    internal static JsonObject Run(string installRoot, string sourceRoot, bool apply)
    {
        string install = Checked(installRoot, "directory"), source = Checked(sourceRoot, "directory");
        Require(!install.Equals(source, StringComparison.OrdinalIgnoreCase), "InstallRoot and SourceRoot must differ.");
        string policy = Path.Combine(install, "policy.json"), bindingPath = Path.Combine(install, "binding.json"), serve = Path.Combine(install, "serve-input");
        string quarantine = Path.Combine(install, "quarantine", "half-published-20260914"), backup = Path.Combine(install, "maintenance", "publication-fixes-20260914");
        var oldBinding = AssertBinding(install); string policyHash = CheckedHash(policy), bindingHash = CheckedHash(bindingPath);
        var copies = new JsonArray();
        foreach (string name in PolicyMaintenance.RuntimeNames(source))
        {
            string from = Path.Combine(source, name), to = Path.Combine(install, name);
            Require(oldBinding["runtime_files"].Array().Count(item => item!["path"].Text()?.Equals(to, StringComparison.OrdinalIgnoreCase) == true) == 1, "Runtime missing from binding: " + to);
            copies.Add((JsonNode)new JsonObject { ["source"] = from, ["destination"] = to, ["old_sha256"] = CheckedHash(to), ["new_sha256"] = CheckedHash(from) });
        }
        var moves = new JsonArray();
        foreach (var (id, fingerprint) in Identities)
        {
            string from = Checked(Path.Combine(serve, id), "directory"), to = Path.GetFullPath(Path.Combine(quarantine, id));
            Require(Path.GetDirectoryName(from)!.Equals(serve, StringComparison.OrdinalIgnoreCase) && Path.GetDirectoryName(to)!.Equals(quarantine, StringComparison.OrdinalIgnoreCase), "Move escaped the approved roots.");
            string[] children = Directory.GetFileSystemEntries(from); Require(children.Length == 1 && Path.GetFileName(children[0]) == "request.json" && File.Exists(children[0]), "Directory is no longer request-only: " + from);
            string requestPath = Path.Combine(from, "request.json"); var request = Read(requestPath);
            Require(request["content_fingerprint"].Text() == fingerprint, "Fingerprint changed: " + requestPath);
            string record = Path.Combine(request["business"]!["cwd"].String(), ".codex-command-records", id), claim = Path.Combine(serve, "_claims", fingerprint, "claim.json");
            Require(!Path.Exists(record) && !Path.Exists(claim), "Execution or claim now exists; re-review before moving: " + from);
            moves.Add((JsonNode)new JsonObject { ["source"] = from, ["destination"] = to, ["request_sha256"] = CheckedHash(requestPath) });
        }
        foreach (string path in new[] { backup, quarantine })
        {
            Require(!Path.Exists(path), "Maintenance target already exists: " + path);
            string parent = Path.GetDirectoryName(path)!;
            if (Path.Exists(parent)) _ = Checked(parent, "directory");
        }
        var active = new JsonArray();
        foreach (var process in Process.GetProcessesByName("CommandEntry"))
            using (process)
            {
                string? path = process.MainModule?.FileName;
                if (path is not null && Path.GetDirectoryName(path)!.Equals(install, StringComparison.OrdinalIgnoreCase))
                    active.Add((JsonNode)new JsonObject { ["ProcessId"] = process.Id, ["Name"] = process.ProcessName });
            }
        string manifest = Path.Combine(backup, "manifest.json");
        var plan = new JsonObject { ["apply"] = apply, ["copies"] = copies, ["moves"] = moves, ["backup_directory"] = backup,
            ["manifest"] = manifest, ["policy_sha256"] = policyHash, ["active_processes"] = active, ["binding_update"] = bindingPath };
        if (!apply) return plan;
        Require(active.Count == 0, "Stop the listed command-entry servers and children before applying.");
        Directory.CreateDirectory(backup);
        foreach (var item in copies)
        {
            string from = item!["source"].String(), to = item["destination"].String(), saved = Path.Combine(backup, Path.GetFileName(to));
            Require(CheckedHash(from) == item["new_sha256"].Text() && CheckedHash(to) == item["old_sha256"].Text(), "Runtime changed after preflight.");
            File.Copy(to, saved); Require(CheckedHash(saved) == item["old_sha256"].Text(), "Backup mismatch: " + saved);
        }
        string savedBinding = Path.Combine(backup, "binding.json"); File.Copy(bindingPath, savedBinding); Require(CheckedHash(savedBinding) == bindingHash, "Binding changed after preflight.");
        WriteNew(manifest, plan);
        foreach (var item in copies)
        {
            File.Copy(item!["source"].String(), item["destination"].String(), overwrite: true);
            Require(CheckedHash(item["destination"].String()) == item["new_sha256"].Text(), "Installed hash mismatch.");
        }
        _ = PolicyMaintenance.Update(install, policy, null, null); _ = AssertBinding(install);
        Require(CheckedHash(policy) == policyHash, "Policy bytes changed during re-pin."); Directory.CreateDirectory(quarantine);
        foreach (var item in moves)
        {
            string from = item!["source"].String(), to = item["destination"].String();
            Require(CheckedHash(Path.Combine(from, "request.json")) == item["request_sha256"].Text() && !Path.Exists(to), "Orphan changed after preflight.");
            Directory.Move(from, to);
            Require(!Path.Exists(from) && CheckedHash(Path.Combine(to, "request.json")) == item["request_sha256"].Text(), "Quarantine verification failed.");
        }
        return new() { ["state"] = "verified", ["installed_files"] = copies.Count, ["quarantined_directories"] = moves.Count, ["policy_unchanged"] = true, ["manifest"] = manifest };
    }
}
