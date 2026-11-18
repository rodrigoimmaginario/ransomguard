namespace RansomGuard.Core.Signing;

/// <summary>Utilitários de parsing do formato texto do minisign (linhas + base64).</summary>
internal static class MinisignFormat
{
    public static string[] Lines(string fileContent) =>
        fileContent.Replace("\r\n", "\n").Split('\n', StringSplitOptions.None)
                   .Select(l => l.TrimEnd('\r')).ToArray();

    public static byte[] DecodeBase64Line(string fileContent, int lineIndex)
    {
        var lines = Lines(fileContent);
        if (lines.Length <= lineIndex)
            throw new FormatException($"Arquivo minisign deve ter ao menos {lineIndex + 1} linhas.");
        return DecodeBase64(lines[lineIndex], $"linha {lineIndex + 1}");
    }

    public static byte[] DecodeBase64(string line, string what)
    {
        try
        {
            return Convert.FromBase64String(line.Trim());
        }
        catch (FormatException ex)
        {
            throw new FormatException($"Base64 inválido na {what} do arquivo minisign.", ex);
        }
    }
}
