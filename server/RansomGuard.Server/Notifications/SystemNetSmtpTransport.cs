using System.Net;
using System.Net.Mail;
using RansomGuard.Core.Notifications;

namespace RansomGuard.Server.Notifications;

/// <summary>
/// Transporte SMTP real, com <see cref="SmtpClient"/>. Vive no painel (não no Core) porque é o único
/// ponto que fala com a rede — o Core continua testável com o transporte injetado.
///
/// Sem autenticação quando o servidor não pede (relay interno é o caso comum num file server), e com
/// credencial quando o admin a informou.
/// </summary>
public sealed class SystemNetSmtpTransport : ISmtpTransport
{
    public async Task SendAsync(SmtpSettings s, string subject, string body, CancellationToken ct)
    {
        using var client = new SmtpClient(s.Host, s.Port) { EnableSsl = s.UseSsl };
        if (!string.IsNullOrWhiteSpace(s.User))
            client.Credentials = new NetworkCredential(s.User, s.Password);

        using var msg = new MailMessage { From = new MailAddress(s.From), Subject = subject, Body = body };
        foreach (var to in s.To) msg.To.Add(to);

        // SmtpClient.SendMailAsync não aceita CancellationToken nas versões suportadas; o timeout do
        // próprio cliente (padrão 100s) fecha o pior caso, e o canal roda em paralelo aos demais.
        ct.ThrowIfCancellationRequested();
        await client.SendMailAsync(msg);
    }
}
