using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGovernance.Policy;
using Axg.AgentGovernance;
using Xunit;

namespace Axg.AgentGovernance.Tests;

public class AxgPolicyBackendTests
{
    private sealed class FakeAxg(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<(HttpRequestMessage Request, string Body)> Calls { get; } = new();

        private HttpResponseMessage Handle(HttpRequestMessage request)
        {
            Calls.Add((request, request.Content!.ReadAsStringAsync().GetAwaiter().GetResult()));
            return respond(request);
        }

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken ct) => Handle(request);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(Handle(request));
    }

    private static HttpResponseMessage Json(string decision, string? passport = null, HttpStatusCode status = HttpStatusCode.OK)
        => new(status)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                execution_id = "exec-1",
                decision,
                passport,
                passport_id = passport is null ? null : "jti-1",
                reason = $"because {decision}",
                actionable_payload = new { amount = 10, proposed_action = "create_expense" },
                scores = new { risk_level = "medium" },
                approval = decision is "CONFIRM" or "SUGGEST"
                    ? new { ticket = "ticket.jwt", ticket_id = "ticket-1", required_role = "end_user", expires_at = 1790000000L }
                    : null,
            }), Encoding.UTF8, "application/json"),
        };

    private static (AxgPolicyBackend Backend, FakeAxg Handler) Backend(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        var handler = new FakeAxg(respond);
        var backend = new AxgPolicyBackend(
            new AxgPolicyBackendOptions { BaseUrl = new Uri("https://axg.test"), ApiKey = "k-1", AppId = "finnorte" },
            new HttpClient(handler));
        return (backend, handler);
    }

    private static Dictionary<string, object> Context() => new()
    {
        ["agent_did"] = "did:mesh:agent-1",
        ["tool_name"] = "create_expense",
        ["args"] = new Dictionary<string, object> { ["amount"] = 10 },
        ["tenant_id"] = "tenant_a",
        ["permissions"] = new List<object> { "expense:create" },
    };

    [Fact]
    public void Allow_with_passport_allows_and_returns_the_passport()
    {
        var (backend, handler) = Backend(_ => Json("ALLOW", "jwt.passport"));
        var result = backend.Evaluate(Context());

        Assert.True(result.Allowed);
        Assert.Null(result.Error);
        Assert.Equal("jwt.passport", result.Metadata["passport"]);
        Assert.Equal("jti-1", result.Metadata["passport_id"]);
        Assert.False((bool)result.Metadata["requires_approval"]);
        Assert.Contains("\"proposed_action\":\"create_expense\"", (string)result.Metadata["actionable_payload"]);
        Assert.Single(handler.Calls);
    }

    [Theory]
    [InlineData("CONFIRM", true)]
    [InlineData("SUGGEST", true)]
    [InlineData("BLOCK", false)]
    public void Other_decisions_deny(string decision, bool requiresApproval)
    {
        var (backend, _) = Backend(_ => Json(decision));
        var result = backend.Evaluate(Context());

        Assert.False(result.Allowed);
        Assert.Null(result.Error);
        Assert.Equal(decision, result.Metadata["axg_decision"]);
        Assert.Equal(requiresApproval, result.Metadata["requires_approval"]);
        Assert.StartsWith($"AXG {decision}:", result.Reason);
    }

    [Fact]
    public void Allow_without_passport_denies()
    {
        var (backend, _) = Backend(_ => Json("ALLOW"));
        Assert.False(backend.Evaluate(Context()).Allowed);
    }

    [Fact]
    public void Http_error_fails_closed()
    {
        var (backend, _) = Backend(_ => Json("ALLOW", "p", HttpStatusCode.Unauthorized));
        var result = backend.Evaluate(Context());
        Assert.False(result.Allowed);
        Assert.Equal("AXG returned HTTP 401", result.Error);
    }

    [Fact]
    public void Unreadable_response_fails_closed()
    {
        var (backend, _) = Backend(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>") });
        Assert.Equal("AXG returned an unreadable response", backend.Evaluate(Context()).Error);
    }

    [Fact]
    public async Task Network_errors_and_timeouts_fail_closed_on_both_paths()
    {
        var (down, _) = Backend(_ => throw new HttpRequestException("connection refused"));
        Assert.StartsWith("AXG unavailable", down.Evaluate(Context()).Error);
        Assert.StartsWith("AXG unavailable", (await down.EvaluateAsync(Context(), CancellationToken.None)).Error);

        var (slow, _) = Backend(_ => throw new TaskCanceledException("timeout"));
        Assert.False((await slow.EvaluateAsync(Context(), CancellationToken.None)).Allowed);
    }

    [Fact]
    public async Task Async_path_maps_like_the_sync_path()
    {
        var (backend, _) = Backend(_ => Json("ALLOW", "jwt.passport"));
        var result = await backend.EvaluateAsync(Context(), CancellationToken.None);
        Assert.True(result.Allowed);
    }

    [Fact]
    public void Request_carries_key_agent_permissions_tool_and_tenant()
    {
        var (backend, handler) = Backend(_ => Json("CONFIRM"));
        backend.Evaluate(Context());

        var (request, body) = handler.Calls.Single();
        Assert.Equal("https://axg.test/v1/decisions", request.RequestUri!.ToString());
        Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
        Assert.Equal("k-1", request.Headers.Authorization.Parameter);

        var sent = JsonNode.Parse(body)!;
        Assert.Equal("finnorte", sent["app_id"]!.GetValue<string>());
        Assert.Equal("finnorte", sent["plugin_id"]!.GetValue<string>());
        Assert.Equal("tenant_a", sent["tenant_id"]!.GetValue<string>());
        Assert.Equal("create_expense", sent["action_type"]!.GetValue<string>());
        Assert.Equal("agt", sent["source"]!.GetValue<string>());
        Assert.Equal(10, sent["payload"]!["amount"]!.GetValue<int>());
        Assert.Equal("did:mesh:agent-1", sent["agent"]!["id"]!.GetValue<string>());
        Assert.Equal("expense:create", sent["agent"]!["permissions"]![0]!.GetValue<string>());
    }

    [Fact]
    public void Missing_context_uses_safe_defaults()
    {
        var (backend, handler) = Backend(_ => Json("BLOCK"));
        backend.Evaluate(new Dictionary<string, object>());
        var sent = JsonNode.Parse(handler.Calls.Single().Body)!;
        Assert.Equal("default", sent["tenant_id"]!.GetValue<string>());
        Assert.Equal("unknown-agent", sent["agent"]!["id"]!.GetValue<string>());
        Assert.Empty(sent["agent"]!["permissions"]!.AsArray());
    }

    // ── Inside the real Agent Governance Toolkit PolicyEngine ──

    private static PolicyEngine EngineWithAllowAllRule(AxgPolicyBackend backend)
    {
        var engine = new PolicyEngine();
        engine.LoadYaml("name: native\nrules:\n  - name: allow-all\n    condition: \"true\"\n    action: allow\n");
        engine.AddExternalBackend(backend);
        return engine;
    }

    [Fact]
    public void Axg_confirmation_overrides_a_native_allow_rule()
    {
        var (backend, _) = Backend(_ => Json("CONFIRM"));
        var decision = EngineWithAllowAllRule(backend).Evaluate("did:mesh:agent-1", Context());
        Assert.False(decision.Allowed);
        Assert.Contains("axg", decision.Reason);
    }

    [Fact]
    public void Axg_allow_reaches_the_host_through_the_sink()
    {
        var (backend, handler) = Backend(_ => Json("ALLOW", "jwt.passport"));
        var context = Context();
        var sink = AxgDecisionSink.Attach(context);

        var decision = EngineWithAllowAllRule(backend).Evaluate("did:mesh:agent-1", context);

        Assert.True(decision.Allowed);
        Assert.Equal("did:mesh:agent-1", JsonNode.Parse(handler.Calls.Single().Body)!["agent"]!["id"]!.GetValue<string>());
        Assert.True(sink.Allowed);
        Assert.Equal("ALLOW", sink.Decision);
        Assert.Equal("jwt.passport", sink.Passport);
        Assert.Equal("jti-1", sink.PassportId);
        Assert.Equal("exec-1", sink.ExecutionId);
        Assert.Equal("medium", sink.RiskLevel);
        Assert.Contains("create_expense", sink.ActionablePayloadJson);
        Assert.False(sink.RequiresApproval);
        Assert.Null(sink.ApprovalTicket);
        Assert.Null(sink.ApprovalExpiresAt);
    }

    [Fact]
    public async Task Sink_reports_confirmations_and_outages()
    {
        var (confirming, _) = Backend(_ => Json("CONFIRM"));
        var context = Context();
        var sink = AxgDecisionSink.Attach(context);
        Assert.False(EngineWithAllowAllRule(confirming).Evaluate("did:mesh:agent-1", context).Allowed);
        Assert.True(sink.RequiresApproval);
        Assert.Null(sink.Passport);
        Assert.Equal("ticket.jwt", sink.ApprovalTicket);
        Assert.Equal("ticket-1", sink.ApprovalTicketId);
        Assert.Equal("end_user", sink.ApprovalRequiredRole);
        Assert.Equal(1790000000L, sink.ApprovalExpiresAt);

        var (down, _) = Backend(_ => throw new HttpRequestException("down"));
        var context2 = Context();
        var sink2 = AxgDecisionSink.Attach(context2);
        await down.EvaluateAsync(context2, CancellationToken.None);
        Assert.StartsWith("AXG unavailable", sink2.Error);
        Assert.Null(sink2.Decision);
    }

    [Fact]
    public void Axg_outage_denies_inside_the_engine()
    {
        var (backend, _) = Backend(_ => throw new HttpRequestException("down"));
        Assert.False(EngineWithAllowAllRule(backend).Evaluate("did:mesh:agent-1", Context()).Allowed);
    }
}
