using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Core.Fsrm;

/// <summary>
/// Catálogo de padrões de ransomware (extensões maliciosas e nomes de ransom notes) que alimenta
/// o file group do FSRM. É a evolução do `metadados.txt` do repositório original do owner: na
/// fatia 3 passa a ser distribuído assinado (minisign, chave offline) e atualizado sozinho.
/// </summary>
public sealed class RansomwareCatalog
{
    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    /// <summary>Padrões de inclusão do file group (ex.: "*.locked", "*.crypted", "HOW_TO_DECRYPT*").</summary>
    [JsonPropertyName("patterns")]
    public IReadOnlyList<string> Patterns { get; init; } = new List<string>();

    /// <summary>G7: padrões (curinga *) de nome de nota de resgate, somados aos embutidos. Opcional.</summary>
    [JsonPropertyName("notePatterns")]
    public IReadOnlyList<string>? NotePatterns { get; init; }

    /// <summary>G7: afinação dos limiares do motor sem relançar o agente. Opcional; cada campo nulo mantém o padrão.</summary>
    [JsonPropertyName("tuning")]
    public DetectionTuning? Tuning { get; init; }

    /// <summary>Extensões "*.ext" do catálogo como ".ext" (sem curinga interno), para o motor de detecção.</summary>
    [JsonIgnore]
    public IReadOnlySet<string> Extensions => Patterns
        .Where(p => p.StartsWith("*.", StringComparison.Ordinal) && !p[2..].Contains('*') && !p[2..].Contains('?'))
        .Select(p => p[1..]).ToHashSet(StringComparer.OrdinalIgnoreCase);

    public static RansomwareCatalog FromJson(string json)
        => JsonSerializer.Deserialize<RansomwareCatalog>(json)
           ?? throw new FormatException("Catálogo inválido.");

    public string ToJson()
        => JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
}

/// <summary>G7 — limiares que o catálogo assinado pode afinar. Faixas validadas pela <see cref="CatalogPolicy"/>.</summary>
public sealed class DetectionTuning
{
    [JsonPropertyName("massThreshold")] public int? MassThreshold { get; init; }
    [JsonPropertyName("rollingWindowThreshold")] public int? RollingWindowThreshold { get; init; }
    [JsonPropertyName("slowThreshold")] public int? SlowThreshold { get; init; }
    [JsonPropertyName("readThreshold")] public int? ReadThreshold { get; init; }
    [JsonPropertyName("knownExtensionThreshold")] public int? KnownExtensionThreshold { get; init; }
    [JsonPropertyName("minNoteDirectories")] public int? MinNoteDirectories { get; init; }
}
