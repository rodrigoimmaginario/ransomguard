using RansomGuard.Agent.Sensors;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// O cursor decide de onde o coletor retoma depois de um reinício do serviço. Errar aqui tem dois
/// desfechos ruins e simétricos: retomar do zero reprocessa o log inteiro e dispara uma tempestade
/// de alertas falsos; retomar do "agora" abre um buraco cego exatamente durante a janela em que o
/// serviço esteve parado — que é quando um EDR killer teria agido.
/// </summary>
public class EventCursorTests
{
    private sealed class MemoriaVolatil : ICursorStore
    {
        public string? Conteudo;
        public int Gravacoes;
        public Exception? FalhaAoLer;
        public Exception? FalhaAoGravar;

        public string? Read() => FalhaAoLer is null ? Conteudo : throw FalhaAoLer;
        public void Write(string content)
        {
            if (FalhaAoGravar is not null) throw FalhaAoGravar;
            Gravacoes++;
            Conteudo = content;
        }
    }

    [Fact]
    public void Primeira_execucao_comeca_do_zero()
        => Assert.Equal(0, new EventCursor(new MemoriaVolatil()).LastRecordId);

    /// <summary>
    /// "Nunca rodei aqui" é diferente de "meu cursor foi zerado porque limparam o log": no primeiro caso o
    /// coletor parte do evento mais novo; no segundo, relê o log novo desde o começo.
    /// </summary>
    [Fact]
    public void Distingue_nunca_ter_rodado_de_ter_um_cursor_zerado()
    {
        Assert.False(new EventCursor(new MemoriaVolatil()).HasSavedPosition);
        Assert.True(new EventCursor(new MemoriaVolatil { Conteudo = "0" }).HasSavedPosition);
        Assert.True(new EventCursor(new MemoriaVolatil { Conteudo = "731" }).HasSavedPosition);
        Assert.False(new EventCursor(new MemoriaVolatil { Conteudo = "lixo" }).HasSavedPosition);
    }

    [Fact]
    public void Linha_de_base_fixa_e_persiste_a_posicao_inicial_mesmo_que_seja_zero()
    {
        var store = new MemoriaVolatil();
        var c = new EventCursor(store);

        c.Baseline(0);

        Assert.True(c.HasSavedPosition);
        Assert.Equal("0", store.Conteudo);
        Assert.True(new EventCursor(store).HasSavedPosition);   // não refaz a linha de base no próximo reinício

        var outro = new EventCursor(new MemoriaVolatil());
        outro.Baseline(4200);
        Assert.Equal(4200, outro.LastRecordId);
    }

    [Fact]
    public void Cursor_zerado_por_limpeza_do_log_continua_sendo_posicao_conhecida()
    {
        var store = new MemoriaVolatil();
        var c = new EventCursor(store);
        c.Advance(1000);

        c.NoticeNewest(3);

        Assert.True(c.HasSavedPosition);
        Assert.True(new EventCursor(store).HasSavedPosition);
    }

    [Fact]
    public void Avanca_e_persiste_o_maior_id_visto()
    {
        var store = new MemoriaVolatil();
        var c = new EventCursor(store);

        c.Advance(100);
        c.Advance(250);

        Assert.Equal(250, c.LastRecordId);
        Assert.Equal(250, new EventCursor(store).LastRecordId);   // sobrevive ao reinício
    }

    /// <summary>O log não garante ordem; um id menor chegando depois não pode fazer o cursor voltar.</summary>
    [Fact]
    public void Nao_retrocede_com_evento_fora_de_ordem()
    {
        var c = new EventCursor(new MemoriaVolatil());

        c.Advance(500);
        c.Advance(120);

        Assert.Equal(500, c.LastRecordId);
    }

    [Fact]
    public void So_grava_quando_o_valor_realmente_avanca()
    {
        var store = new MemoriaVolatil();
        var c = new EventCursor(store);

        c.Advance(10);
        var apos = store.Gravacoes;
        c.Advance(10);
        c.Advance(5);

        Assert.Equal(apos, store.Gravacoes);   // nada de escrever em disco a cada ciclo à toa
    }

    [Fact]
    public void Filtra_eventos_ja_processados()
    {
        var c = new EventCursor(new MemoriaVolatil());
        c.Advance(100);

        Assert.False(c.IsNew(99));
        Assert.False(c.IsNew(100));
        Assert.True(c.IsNew(101));
    }

    /// <summary>
    /// Quando o Security log é **limpo** — e limpar o log é passo de playbook de ransomware para
    /// apagar rastro — os RecordIds recomeçam do 1. O cursor antigo passa a ser maior que qualquer
    /// evento existente, e o agente ficaria cego para sempre.
    ///
    /// O sinal é o **maior** id do log estar abaixo do cursor. Usar o menor id não serve: num log
    /// normal que nunca encheu, o menor id também é baixo.
    /// </summary>
    [Fact]
    public void Log_limpo_reinicia_o_cursor()
    {
        var c = new EventCursor(new MemoriaVolatil());
        c.Advance(1_000_000);

        c.NoticeNewest(12);          // o log inteiro agora vai até 12: foi limpo

        Assert.Equal(0, c.LastRecordId);
        Assert.True(c.IsNew(13));
    }

    [Fact]
    public void Log_normal_nao_dispara_reinicio()
    {
        var c = new EventCursor(new MemoriaVolatil());
        c.Advance(1000);

        c.NoticeNewest(1200);        // log seguindo em frente, como esperado

        Assert.Equal(1000, c.LastRecordId);
    }

    /// <summary>Cursor exatamente no fim do log é o caso normal de "nada novo desde o último ciclo".</summary>
    [Fact]
    public void Cursor_na_ponta_do_log_nao_e_confundido_com_limpeza()
    {
        var c = new EventCursor(new MemoriaVolatil());
        c.Advance(1000);

        c.NoticeNewest(1000);

        Assert.Equal(1000, c.LastRecordId);
    }

    [Fact]
    public void Log_vazio_apos_limpeza_tambem_reinicia()
    {
        var c = new EventCursor(new MemoriaVolatil());
        c.Advance(500);

        c.NoticeNewest(0);           // log sem nenhum evento

        Assert.Equal(0, c.LastRecordId);
    }

    // ── Robustez: o cursor nunca pode derrubar o agente ─────────────────────────────────────

    [Fact]
    public void Conteudo_corrompido_e_tratado_como_primeira_execucao()
    {
        var store = new MemoriaVolatil { Conteudo = "isto não é um número" };
        Assert.Equal(0, new EventCursor(store).LastRecordId);
    }

    [Fact]
    public void Falha_de_leitura_nao_derruba_o_agente()
    {
        var store = new MemoriaVolatil { FalhaAoLer = new UnauthorizedAccessException() };
        Assert.Equal(0, new EventCursor(store).LastRecordId);
    }

    /// <summary>
    /// Disco cheio ou permissão negada não podem parar a coleta: perder o cursor custa
    /// reprocessamento, parar de coletar custa o ataque.
    /// </summary>
    [Fact]
    public void Falha_de_gravacao_nao_derruba_o_agente()
    {
        var store = new MemoriaVolatil { FalhaAoGravar = new IOException("disco cheio") };
        var c = new EventCursor(store);

        c.Advance(42);

        Assert.Equal(42, c.LastRecordId);   // segue em memória
    }
}
