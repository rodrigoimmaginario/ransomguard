namespace RansomGuard.Agent.Sensors;

/// <summary>Onde o cursor é guardado. Abstraído para o cursor ser testável sem disco.</summary>
public interface ICursorStore
{
    string? Read();
    void Write(string content);
}

/// <summary>
/// Guarda o último evento processado, para o coletor retomar no lugar certo depois de um reinício
/// do serviço.
///
/// Os dois erros possíveis são simétricos e ambos graves: retomar do zero reprocessa o log inteiro
/// e vira tempestade de alertas falsos; retomar do "agora" abre um buraco cego bem na janela em que
/// o serviço esteve parado — que é exatamente quando um EDR killer teria agido.
///
/// Falhar ao ler ou gravar **nunca** derruba o agente: perder o cursor custa reprocessamento,
/// parar de coletar custa o ataque.
/// </summary>
public sealed class EventCursor
{
    private readonly ICursorStore _store;

    public long LastRecordId { get; private set; }

    /// <summary>
    /// Há uma posição conhecida (mesmo que 0, depois de uma limpeza do log)? Falso só quando o agente
    /// nunca rodou nesta máquina ou perdeu o arquivo do cursor — aí o coletor fixa a linha de base no
    /// evento mais novo em vez de tratar todo o histórico do log como atividade recente.
    /// </summary>
    public bool HasSavedPosition { get; private set; }

    public EventCursor(ICursorStore store)
    {
        _store = store;
        try
        {
            if (long.TryParse(_store.Read(), out var saved) && saved >= 0)
            {
                LastRecordId = saved;
                HasSavedPosition = true;
            }
        }
        catch (Exception)
        {
            LastRecordId = 0;   // conteúdo ilegível ou sem permissão: sem posição conhecida
        }
    }

    /// <summary>Fixa a posição inicial (primeira execução). Persiste sempre, inclusive 0 (log vazio).</summary>
    public void Baseline(long newestRecordId)
    {
        LastRecordId = Math.Max(0, newestRecordId);
        HasSavedPosition = true;
        try { _store.Write(LastRecordId.ToString()); }
        catch (Exception) { /* segue em memória: coletar importa mais que lembrar */ }
    }

    /// <summary>Este evento ainda não foi processado?</summary>
    public bool IsNew(long recordId) => recordId > LastRecordId;

    /// <summary>Marca o evento como processado. Só persiste quando o valor de fato avança.</summary>
    public void Advance(long recordId)
    {
        if (recordId <= LastRecordId) return;   // log não garante ordem; nunca retrocede
        LastRecordId = recordId;
        try { _store.Write(recordId.ToString()); }
        catch (Exception) { /* segue em memória: coletar importa mais que lembrar */ }
    }

    /// <summary>
    /// Informa o **maior** RecordId presente no log. Se ele estiver abaixo do cursor, o log foi
    /// limpo e os ids recomeçaram do 1 — e limpar o Security log é passo de playbook de ransomware
    /// para apagar rastro. Ficar preso no id antigo cegaria o agente permanentemente, justamente
    /// depois de um evento que merece atenção.
    ///
    /// O menor id do log não serve como sinal: num log que nunca encheu, ele também é baixo.
    /// </summary>
    public void NoticeNewest(long newestRecordId)
    {
        if (newestRecordId >= LastRecordId) return;   // log seguindo em frente: normal

        LastRecordId = 0;
        HasSavedPosition = true;
        try { _store.Write("0"); } catch (Exception) { /* idem */ }
    }
}

/// <summary>Cursor em arquivo — usado pelo serviço Windows (ProgramData).</summary>
public sealed class FileCursorStore : ICursorStore
{
    private readonly string _path;

    public FileCursorStore(string path)
    {
        _path = path;
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }

    public string? Read() => File.Exists(_path) ? File.ReadAllText(_path).Trim() : null;

    public void Write(string content) => File.WriteAllText(_path, content);
}
