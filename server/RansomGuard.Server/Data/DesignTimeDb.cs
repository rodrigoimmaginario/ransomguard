using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace RansomGuard.Server.Data;

/// <summary>
/// C2 — só para a ferramenta de migrações (<c>dotnet ef migrations add Nome --project server/RansomGuard.Server</c>):
/// cria o contexto sem subir o painel (que geraria segredos e abriria portas).
/// </summary>
public sealed class DesignTimeDb : IDesignTimeDbContextFactory<RansomGuardDb>
{
    public RansomGuardDb CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite("Data Source=design-time.db").Options);
}
