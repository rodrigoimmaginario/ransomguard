using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace RansomGuard.Core.Security;

/// <summary>
/// D9/B2 — pasta de dados que só o sistema, os administradores e a conta do próprio serviço alcançam.
///
/// Por quê: uma pasta criada sob <c>%ProgramData%</c> herda a permissão padrão, que deixa qualquer usuário do
/// servidor LER o que está lá e CRIAR arquivos. No agente isso permitia injetar um lote na fila (enviado ao painel
/// como se fosse do agente) e plantar o pin do painel antes do primeiro contato; no painel, ler a chave que assina
/// as políticas.
/// </summary>
[SupportedOSPlatform("windows")]
public static class SecureDirectory
{
    /// <summary>Identidades amplas que não podem ter acesso à pasta de dados.</summary>
    private static readonly WellKnownSidType[] Broad =
    {
        WellKnownSidType.WorldSid, WellKnownSidType.AuthenticatedUserSid, WellKnownSidType.BuiltinUsersSid,
        WellKnownSidType.InteractiveSid, WellKnownSidType.AnonymousSid, WellKnownSidType.BuiltinGuestsSid,
        WellKnownSidType.NetworkSid
    };

    /// <summary>
    /// Cria a pasta (se preciso) e a restringe. Idempotente: uma pasta já restrita não é reescrita — só ganha a
    /// identidade do processo atual, se faltar (o serviço pode rodar com uma conta gerenciada em vez de SYSTEM).
    /// </summary>
    public static void Ensure(string path)
    {
        var dir = Directory.CreateDirectory(path);
        using var me = WindowsIdentity.GetCurrent();
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        FileSystemAccessRule Full(IdentityReference who) =>
            new(who, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow);

        if (IsRestricted(path))
        {
            if (me.User is not { } user || HasAccess(dir, user)) return;
            var current = dir.GetAccessControl(AccessControlSections.Access);
            current.AddAccessRule(Full(user));
            dir.SetAccessControl(current);
            return;
        }

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);   // não herda a permissão de ProgramData
        security.AddAccessRule(Full(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)));
        security.AddAccessRule(Full(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)));
        if (me.User is { } self) security.AddAccessRule(Full(self));
        dir.SetAccessControl(security);
    }

    /// <summary>A pasta não herda permissões e nenhuma identidade ampla tem acesso?</summary>
    public static bool IsRestricted(string path)
    {
        var security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access);
        return security.AreAccessRulesProtected && BroadAccess(path).Count == 0;
    }

    /// <summary>Identidades amplas (Todos, Usuários, Usuários Autenticados…) com permissão na pasta — deve ser vazio.</summary>
    public static IReadOnlyList<string> BroadAccess(string path)
    {
        var broad = Broad.Select(t => new SecurityIdentifier(t, null)).ToHashSet();
        var security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access);
        var found = new List<string>();
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference is SecurityIdentifier sid && broad.Contains(sid))
                found.Add(sid.Value);
        return found;
    }

    private static bool HasAccess(DirectoryInfo dir, SecurityIdentifier user)
    {
        var groups = new HashSet<SecurityIdentifier> { user };
        using (var me = WindowsIdentity.GetCurrent())
            foreach (var g in me.Groups ?? new IdentityReferenceCollection())
                if (g is SecurityIdentifier sid) groups.Add(sid);
        foreach (FileSystemAccessRule rule in dir.GetAccessControl(AccessControlSections.Access).GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference is SecurityIdentifier sid && groups.Contains(sid)
                && rule.FileSystemRights.HasFlag(FileSystemRights.Modify))
                return true;
        return false;
    }
}
