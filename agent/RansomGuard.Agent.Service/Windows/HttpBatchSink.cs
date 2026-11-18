using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using RansomGuard.Agent;
using RansomGuard.Core.Auth;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// Envia o lote coletado ao painel (POST /api/ingest), assinado com a chave deste agente (B1). Não há segredo
/// compartilhado: o painel confere a assinatura contra a chave enrolada para este servidor.
/// </summary>
public sealed class HttpBatchSink(HttpClient http, AgentIdentity identity, AgentEnroller enroller, ILogger<HttpBatchSink> log) : IBatchSink
{
    /// <summary>Espelha o IngestResult do painel — só o que o agente consome: política e comandos assinados.</summary>
    private sealed record IngestReply(SignedAssertion? Policy, SignedAssertion? Commands);

    public async Task<BatchResponse?> SendAsync(AgentBatch batch, CancellationToken ct = default)
    {
        try
        {
            // Sem enrolamento não há o que mandar: o painel recusaria. O lote fica na fila do agente.
            if (!await enroller.EnsureEnrolledAsync(ct)) return null;

            var body = JsonSerializer.SerializeToUtf8Bytes(batch, JsonSerializerOptions.Web);
            var timestamp = BatchSignature.Timestamp(DateTime.UtcNow);
            using var request = new HttpRequestMessage(HttpMethod.Post, "/api/ingest") { Content = new ByteArrayContent(body) };
            request.Content.Headers.ContentType = new("application/json");
            request.Headers.Add(BatchSignature.AgentHeader, identity.Server);
            request.Headers.Add(BatchSignature.TimestampHeader, timestamp);
            request.Headers.Add(BatchSignature.SignatureHeader, BatchSignature.Sign(identity.Key, identity.Server, timestamp, body));

            using var resp = await http.SendAsync(request, ct);
            if (!resp.IsSuccessStatusCode)
            {
                await ExplainRefusalAsync(resp, ct);
                return null;
            }

            // F33: política e comandos vêm assinados; o AgentCycle só obedece ao que verifica contra a chave fixada.
            var reply = await resp.Content.ReadFromJsonAsync<IngestReply>(cancellationToken: ct);
            return reply is null ? null : new BatchResponse(reply.Policy, reply.Commands);
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Falha ao enviar lote ao servidor (será retentado no próximo ciclo).");
            return null;   // sem contato: o agente mantém a política vigente (fail-safe)
        }
    }

    /// <summary>O painel diz por que recusou; o agente registra em palavras e, se foi esquecido pelo painel, volta a se enrolar.</summary>
    private async Task ExplainRefusalAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        string error = "", code = "";
        try
        {
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.TryGetProperty("error", out var e)) error = e.GetString() ?? "";
            if (doc.RootElement.TryGetProperty("code", out var c)) code = c.GetString() ?? "";
        }
        catch (Exception) { /* resposta sem corpo legível */ }

        if (resp.StatusCode == HttpStatusCode.Unauthorized && code == "not-enrolled")
        {
            identity.ClearEnrollment();
            log.LogError("O painel não reconhece este agente (revogado, ou painel reinstalado). É preciso enrolar de novo com um token novo.");
        }
        else if (resp.StatusCode == HttpStatusCode.Conflict)
            log.LogInformation("O painel já tinha recebido este lote.");
        else
            log.LogWarning("Lote recusado pelo painel ({Status}): {Error}", (int)resp.StatusCode, error);
    }
}
