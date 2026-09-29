using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGovernance.Policy;

namespace Axg.AgentGovernance;

/// <summary>
/// Configuration for <see cref="AxgPolicyBackend"/>.
/// </summary>
public sealed class AxgPolicyBackendOptions
{
    /// <summary>AXG base URL, e.g. https://axg.internal:8090.</summary>
    public required Uri BaseUrl { get; init; }

    /// <summary>This backend's key, registered in AXG_CLIENTS.</summary>
    public required string ApiKey { get; init; }

    /// <summary>Passport audience: the app/system the governed tools act on.</summary>
    public required string AppId { get; init; }

    /// <summary>AXG policy plugin; defaults to <see cref="AppId"/>.</summary>
    public string? PluginId { get; init; }

    /// <summary>Context key holding the tool/action name.</summary>
    public string ActionKey { get; init; } = "tool_name";

    /// <summary>Context key holding the tool arguments (a dictionary).</summary>
    public string PayloadKey { get; init; } = "args";

    /// <summary>Context key holding the tenant id.</summary>
    public string TenantKey { get; init; } = "tenant_id";

    /// <summary>Context key holding the agent's permissions (strings), capped by AXG_CLIENTS.</summary>
    public string PermissionsKey { get; init; } = "permissions";

    /// <summary>Tenant used when the context carries none.</summary>
    public string DefaultTenant { get; init; } = "default";

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);
}

/// <summary>
/// Per-evaluation receiver for AXG's result. The Agent Governance Toolkit (5.0.0) does not propagate
/// backend metadata into <c>PolicyDecision</c>, so the host puts a sink in the evaluation context
/// under <see cref="ContextKey"/> and reads the Passport from it after <c>PolicyEngine.Evaluate</c>.
/// </summary>
public sealed class AxgDecisionSink
{
    public const string ContextKey = "axg.sink";

    public string? Decision { get; internal set; }
    public bool Allowed { get; internal set; }
    public bool RequiresApproval { get; internal set; }
    public string? Reason { get; internal set; }
    public string? Error { get; internal set; }
    public string? ExecutionId { get; internal set; }
    public string? Passport { get; internal set; }
    public string? PassportId { get; internal set; }
    /// <summary>Authorized payload (JSON) the Passport hash covers; the tool verifies against it.</summary>
    public string? ActionablePayloadJson { get; internal set; }
    public string? RiskLevel { get; internal set; }

    /// <summary>Adds a new sink to <paramref name="context"/> and returns it.</summary>
    public static AxgDecisionSink Attach(IDictionary<string, object> context)
    {
        var sink = new AxgDecisionSink();
        context[ContextKey] = sink;
        return sink;
    }
}

/// <summary>
/// Microsoft Agent Governance Toolkit external backend that asks AXG for every evaluation.
/// <para>
/// ALLOW (with a Passport) is the only allowing outcome. SUGGEST / CONFIRM / BLOCK deny, and
/// <c>Metadata["requires_approval"]</c> tells the host that a human can still approve. Transport and AXG
/// errors are reported through <see cref="ExternalPolicyDecision.Error"/>, which the toolkit treats as
/// deny (fail closed). With DenyOverrides, an AXG deny always wins over native allow rules.
/// </para>
/// <para>
/// The Passport, its id and the authorized payload are returned in <c>Metadata</c>. The toolkit exposes
/// them in <c>PolicyDecision.Metadata["external_backends"]</c>, so the tool can verify the exact call.
/// </para>
/// </summary>
public sealed class AxgPolicyBackend : IExternalPolicyBackend, IDisposable
{
    private readonly AxgPolicyBackendOptions _options;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;

    public AxgPolicyBackend(AxgPolicyBackendOptions options, HttpClient? httpClient = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _ownsHttp = httpClient is null;
        _http = httpClient ?? new HttpClient();
        _http.Timeout = options.Timeout;
    }

    public string Name => "axg";

    /// <summary>
    /// Synchronous path, used by PolicyEngine.Evaluate. It performs real synchronous I/O
    /// (<see cref="HttpClient.Send(HttpRequestMessage)"/>), not sync-over-async.
    /// </summary>
    public ExternalPolicyDecision Evaluate(IReadOnlyDictionary<string, object> context)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            using var response = _http.Send(BuildRequest(context));
            using var reader = new StreamReader(response.Content.ReadAsStream());
            return Report(context, Map(response, reader.ReadToEnd(), watch));
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            return Report(context, Failure($"AXG unavailable: {ex.Message}", watch));
        }
    }

    public async Task<ExternalPolicyDecision> EvaluateAsync(
        IReadOnlyDictionary<string, object> context, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            using var response = await _http.SendAsync(BuildRequest(context), cancellationToken).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return Report(context, Map(response, body, watch));
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            return Report(context, Failure($"AXG unavailable: {ex.Message}", watch));
        }
    }

    private static ExternalPolicyDecision Report(IReadOnlyDictionary<string, object> context, ExternalPolicyDecision result)
    {
        if (Get(context, AxgDecisionSink.ContextKey) is AxgDecisionSink sink)
        {
            var meta = result.Metadata ?? new Dictionary<string, object>();
            string? Text(string key) => meta.TryGetValue(key, out var v) && v is string s && s.Length > 0 ? s : null;
            sink.Allowed = result.Allowed;
            sink.Reason = result.Reason;
            sink.Error = result.Error;
            sink.Decision = Text("axg_decision");
            sink.RequiresApproval = meta.TryGetValue("requires_approval", out var r) && r is true;
            sink.ExecutionId = Text("execution_id");
            sink.Passport = Text("passport");
            sink.PassportId = Text("passport_id");
            sink.ActionablePayloadJson = Text("actionable_payload");
            sink.RiskLevel = Text("risk_level");
        }
        return result;
    }

    internal HttpRequestMessage BuildRequest(IReadOnlyDictionary<string, object> context)
    {
        var agentDid = Get(context, "agent_did") as string ?? "unknown-agent";
        var permissions = (Get(context, _options.PermissionsKey) as IEnumerable<object>)?.Select(p => p.ToString()!)
                          ?? (Get(context, _options.PermissionsKey) as IEnumerable<string>)
                          ?? Enumerable.Empty<string>();

        var decisionRequest = new Dictionary<string, object?>
        {
            ["execution_id"] = $"agt-{Guid.NewGuid()}",
            ["tenant_id"] = Get(context, _options.TenantKey)?.ToString() ?? _options.DefaultTenant,
            ["app_id"] = _options.AppId,
            ["plugin_id"] = _options.PluginId ?? _options.AppId,
            ["agent"] = new Dictionary<string, object?>
            {
                ["id"] = agentDid,
                ["type"] = "agent",
                ["permissions"] = permissions.ToArray(),
            },
            ["source"] = "agt",
            ["action_type"] = Get(context, _options.ActionKey)?.ToString() ?? string.Empty,
            ["payload"] = Get(context, _options.PayloadKey) ?? new Dictionary<string, object>(),
            // An explicit tool call is not an LLM guess: AXG rules and permissions decide
            ["llm"] = new Dictionary<string, object> { ["confidence"] = 1.0 },
            ["metadata"] = new Dictionary<string, object> { ["flow"] = "agt:evaluate" },
        };

        var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_options.BaseUrl, "/v1/decisions"))
        {
            Content = new StringContent(JsonSerializer.Serialize(decisionRequest), Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
        return request;
    }

    private ExternalPolicyDecision Map(HttpResponseMessage response, string body, Stopwatch watch)
    {
        if (!response.IsSuccessStatusCode)
            return Failure($"AXG returned HTTP {(int)response.StatusCode}", watch);

        JsonNode? node;
        try { node = JsonNode.Parse(body); }
        catch (JsonException) { return Failure("AXG returned an unreadable response", watch); }

        var decision = node?["decision"]?.GetValue<string>() ?? "UNKNOWN";
        var passport = node?["passport"]?.GetValue<string>();
        var allowed = decision == "ALLOW" && !string.IsNullOrEmpty(passport);

        return new ExternalPolicyDecision
        {
            Backend = Name,
            Allowed = allowed,
            Reason = $"AXG {decision}: {node?["reason"]?.GetValue<string>() ?? "no reason given"}",
            EvaluationMs = watch.Elapsed.TotalMilliseconds,
            Metadata = new Dictionary<string, object>
            {
                ["axg_decision"] = decision,
                ["requires_approval"] = decision is "CONFIRM" or "SUGGEST",
                ["execution_id"] = node?["execution_id"]?.GetValue<string>() ?? string.Empty,
                ["passport"] = passport ?? string.Empty,
                ["passport_id"] = node?["passport_id"]?.GetValue<string>() ?? string.Empty,
                ["actionable_payload"] = node?["actionable_payload"]?.ToJsonString() ?? "{}",
                ["risk_level"] = node?["scores"]?["risk_level"]?.GetValue<string>() ?? string.Empty,
            },
        };
    }

    private ExternalPolicyDecision Failure(string error, Stopwatch watch) => new()
    {
        Backend = Name,
        Allowed = false,
        Reason = error,
        Error = error,
        EvaluationMs = watch.Elapsed.TotalMilliseconds,
    };

    private static object? Get(IReadOnlyDictionary<string, object> context, string key)
        => context.TryGetValue(key, out var value) ? value : null;

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }
}
