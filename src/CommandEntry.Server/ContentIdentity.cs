using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

// Equivalence for admission only. Persisted fingerprints and retry identities stay unchanged.
internal static class ContentIdentity
{
    internal static string Key(JsonObject form)
    {
        var content = new JsonObject(form.Where(p => RequestShape.StartFields.Contains(p.Key) && p.Key != "previous_execution"
            && !RequestShape.ExecutionKeys.Contains(p.Key) && p.Value is not null).Select(p => KeyValuePair.Create(p.Key, p.Value?.Copy())));
        _ = content["operation"].String("publication_business_unverifiable");
        _ = content["program"].String("publication_business_unverifiable");
        content["args"] ??= new JsonArray();
        content["acceptance"] ??= new JsonArray();
        content["encoding"] ??= "utf-8";
        foreach (string key in new[] { "workdir", "script", "parameters_file", "stdin_file" })
            if (content.ContainsKey(key)) content[key] = PathKey(content[key]);
        foreach (string key in new[] { "input_paths", "required_tools" })
        {
            var paths = content.ArrayOrEmpty(key).Select(PathKey).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            content[key] = new JsonArray(paths.Select(p => (JsonNode?)JsonValue.Create(p)).ToArray());
        }
        content["artifacts"] = new JsonObject(content.ObjectOrEmpty("artifacts")
            .Select(pair => KeyValuePair.Create<string, JsonNode?>(pair.Key, JsonValue.Create(PathKey(pair.Value)))));
        var versions = new JsonObject();
        foreach (var pair in content.ObjectOrEmpty("expected_versions"))
        {
            string path = PathKey(JsonValue.Create(pair.Key));
            Require(!versions.ContainsKey(path) || JsonNode.DeepEquals(versions[path], pair.Value), "conflicting_content_versions");
            versions[path] = pair.Value?.Copy();
        }
        content["expected_versions"] = versions;
        return Digest(content);
    }

    internal static string FromEnvelope(JsonObject envelope)
    {
        var business = (JsonObject)envelope["business"].Object("publication_business_unverifiable").Copy();
        business["workdir"] = business["cwd"]?.Copy();
        Require(business["workdir"] is not null, "publication_business_unverifiable");
        return Key(business);
    }

    private static string PathKey(JsonNode? value) => BusinessPaths.Resolve(RequestShape.Absolute(value)).ToUpperInvariant();
}
