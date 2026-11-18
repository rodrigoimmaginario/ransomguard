using RansomGuard.Core.Auth;
using RansomGuard.Core.Policy;
using RansomGuard.Core.Response;
using RansomGuard.Core.Signing;

namespace RansomGuard.Core.Tests;

/// <summary>F33 — política e comandos assinados: só o painel legítimo configura o agente; nada regride.</summary>
public class AgentPolicyDocumentTests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 9, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] Seed = Enumerable.Range(20, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Evil = Enumerable.Range(70, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] KeyId = [4, 4, 4, 4, 4, 4, 4, 4];
    private static MinisignPublicKey Pub() => MinisignPublicKey.FromRaw(KeyId, Minisign.PublicKeyFromSeed(Seed));

    private static AgentPolicyDocument Doc(string server = "*", long version = 1, string mode = "Block", string maxStep = "DenyUserOnShare") =>
        new(server, version, mode, maxStep, new[] { @"CORP\svc-backup" }, new[] { "10.0.1.9" }, false, T0);

    [Fact]
    public void Maps_to_response_policy_with_case_insensitive_sets()
    {
        var p = Doc().ToResponsePolicy();
        Assert.Equal(ResponseMode.Block, p.Mode);
        Assert.Equal(ResponseStep.DenyUserOnShare, p.MaxStep);
        Assert.Contains(@"corp\SVC-BACKUP", p.AllowlistedUsers);
        Assert.Contains("10.0.1.9", p.AllowlistedIps);
        Assert.False(p.LearningMode);
    }

    [Fact]
    public void Unknown_values_fall_back_to_safe_defaults()
    {
        var p = Doc(mode: "Nuke", maxStep: "Everything").ToResponsePolicy();
        Assert.Equal(ResponseMode.Monitor, p.Mode);
        Assert.Equal(ResponseStep.DenyUserOnShare, p.MaxStep);
    }

    [Fact]
    public void Signed_policy_verifies_for_any_server_when_scoped_to_star()
    {
        var signed = AgentPolicyDocument.Sign(Doc("*"), Seed, KeyId);
        Assert.Equal(PolicyOutcome.Valid, AgentPolicyDocument.Verify(signed, Pub(), "FS01", T0, null).Outcome);
        Assert.Equal(PolicyOutcome.Valid, AgentPolicyDocument.Verify(signed, Pub(), "FS02", T0, null).Outcome);
    }

    [Fact]
    public void Server_scoped_policy_only_applies_to_that_server()
    {
        var signed = AgentPolicyDocument.Sign(Doc("FS01"), Seed, KeyId);
        Assert.Equal(PolicyOutcome.Valid, AgentPolicyDocument.Verify(signed, Pub(), "fs01", T0, null).Outcome);
        Assert.Equal(PolicyOutcome.WrongServer, AgentPolicyDocument.Verify(signed, Pub(), "FS02", T0, null).Outcome);
    }

    [Fact]
    public void Forged_and_tampered_policies_are_rejected()
    {
        Assert.Equal(PolicyOutcome.InvalidSignature, AgentPolicyDocument.Verify(AgentPolicyDocument.Sign(Doc(), Evil, KeyId), Pub(), "FS01", T0, null).Outcome);
        var signed = AgentPolicyDocument.Sign(Doc(mode: "Monitor"), Seed, KeyId);
        var tampered = signed with { Payload = signed.Payload.Replace("\"Monitor\"", "\"Block\"") };
        Assert.Equal(PolicyOutcome.InvalidSignature, AgentPolicyDocument.Verify(tampered, Pub(), "FS01", T0, null).Outcome);
    }

    [Fact]
    public void Older_version_is_a_rollback_and_is_rejected()
    {
        var v2 = AgentPolicyDocument.Sign(Doc(version: 2), Seed, KeyId);
        var v1 = AgentPolicyDocument.Sign(Doc(version: 1, mode: "Monitor"), Seed, KeyId);
        Assert.Equal(PolicyOutcome.Valid, AgentPolicyDocument.Verify(v2, Pub(), "FS01", T0, null).Outcome);
        Assert.Equal(PolicyOutcome.Rollback, AgentPolicyDocument.Verify(v1, Pub(), "FS01", T0, lastVersion: 2).Outcome);
        Assert.Equal(PolicyOutcome.Valid, AgentPolicyDocument.Verify(v2, Pub(), "FS01", T0, lastVersion: 2).Outcome);   // reapresentar a mesma é ok
    }

    [Theory]
    [InlineData("", "x")]
    [InlineData("{bad", "x")]
    public void Malformed_never_throws(string payload, string sig) =>
        Assert.Equal(PolicyOutcome.Malformed, AgentPolicyDocument.Verify(new SignedAssertion(payload, sig), Pub(), "FS01", T0, null).Outcome);

    // ── comandos ──────────────────────────────────────────────────────────────────────────────

    private static CommandEnvelope Env(string server = "FS01", DateTime? issued = null) =>
        new(server, issued ?? T0, (issued ?? T0) + CommandEnvelope.Validity,
            new[] { new AgentCommand("revert-7", AgentCommand.Revert, "DenyUserOnShare", @"\\FS01\Fin", @"CORP\ana", "falso positivo") });

    [Fact]
    public void Command_envelope_verifies_and_maps_to_actions()
    {
        var signed = CommandEnvelope.Sign(Env(), Seed, KeyId);
        var r = CommandEnvelope.Verify(signed, Pub(), "FS01", T0.AddMinutes(1));
        Assert.Equal(PolicyOutcome.Valid, r.Outcome);
        var action = r.Envelope!.Commands[0].ToAction("FS01")!;
        Assert.Equal(ResponseStep.DenyUserOnShare, action.Step);
        Assert.Equal(@"CORP\ana", action.Account);
        Assert.True(ResponseTarget.IsSafe(action));
    }

    [Fact]
    public void Command_envelope_for_other_server_or_expired_or_forged_is_rejected()
    {
        Assert.Equal(PolicyOutcome.WrongServer, CommandEnvelope.Verify(CommandEnvelope.Sign(Env("FS02"), Seed, KeyId), Pub(), "FS01", T0).Outcome);
        Assert.Equal(PolicyOutcome.Rollback, CommandEnvelope.Verify(CommandEnvelope.Sign(Env(), Seed, KeyId), Pub(), "FS01", T0.AddMinutes(20)).Outcome);
        Assert.Equal(PolicyOutcome.InvalidSignature, CommandEnvelope.Verify(CommandEnvelope.Sign(Env(), Evil, KeyId), Pub(), "FS01", T0).Outcome);
    }

    [Fact]
    public void Unknown_command_step_yields_no_action()
    {
        var c = new AgentCommand("x", AgentCommand.Revert, "Teleport", "t", null, "r");
        Assert.Null(c.ToAction("FS01"));
    }
}
