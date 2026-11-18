using System.Runtime.Versioning;
using Microsoft.Win32;
using RansomGuard.Agent.Sensors;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// D1 — tabela de shares de disco deste servidor, lida do registro do LanmanServer. Em processo (sem
/// abrir PowerShell), independente do idioma do Windows, e com cache: shares mudam raramente.
/// Falha de leitura devolve a última tabela boa (ou vazia) — o <see cref="ShareMap"/> ainda monta o
/// UNC pelo nome que vem no evento.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsShareTable
{
    private const string SharesKey = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Shares";

    private readonly string _server;
    private readonly TimeSpan _refresh;
    private readonly Func<DateTime> _clock;
    private readonly object _gate = new();
    private ShareMap? _cached;
    private DateTime _readAt;

    public WindowsShareTable(string server, TimeSpan? refresh = null, Func<DateTime>? clock = null)
    {
        _server = server;
        _refresh = refresh ?? TimeSpan.FromSeconds(60);
        _clock = clock ?? (() => DateTime.UtcNow);
    }

    public ShareMap Current()
    {
        lock (_gate)
        {
            var now = _clock();
            if (_cached is not null && now - _readAt < _refresh) return _cached;
            try
            {
                _cached = new ShareMap(_server, ReadRegistry());
            }
            catch (Exception)
            {
                _cached ??= new ShareMap(_server, Array.Empty<ShareEntry>());
            }
            _readAt = now;
            return _cached;
        }
    }

    public static IReadOnlyList<ShareEntry> ReadRegistry()
    {
        using var key = Registry.LocalMachine.OpenSubKey(SharesKey);
        if (key is null) return Array.Empty<ShareEntry>();
        var values = new List<KeyValuePair<string, string[]>>();
        foreach (var name in key.GetValueNames())
            if (key.GetValue(name) is string[] lines)
                values.Add(new KeyValuePair<string, string[]>(name, lines));
        return ShareMap.ParseLanmanShares(values);
    }
}
