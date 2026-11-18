using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using RansomGuard.Agent.Posture;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// Política de auditoria do Windows, consultada pela API do sistema (<c>AuditQuerySystemPolicy</c>) com o GUID da
/// subcategoria, e ligada pelo <c>auditpol.exe</c> também com o GUID.
///
/// Por que a API e não o texto do <c>auditpol /get</c>: o nome da subcategoria e o texto da configuração mudam com
/// o idioma do Windows ("Success" / "Êxito"). A tentativa anterior, de ler o relatório <c>/r</c> esperando uma
/// coluna numérica, voltou "não sei" no Windows Server 2025 da CI (execução 43904905534); a causa exata não foi
/// isolada naquela execução. A API devolve bits (1 = sucesso, 2 = falha) e não passa por texto nenhum.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsAudit
{
    /// <summary><c>true</c>/<c>false</c> conforme a auditoria de sucesso; <c>null</c> quando não deu para perguntar (sem privilégio).</summary>
    public static bool? IsSuccessEnabled(AuditSubcategory subcategory) =>
        Query(subcategory, out _) is uint bits ? AuditPolicyReader.IsSuccess(bits) : null;

    /// <summary>
    /// Os bits de auditoria da subcategoria, ou <c>null</c> com o código de erro do Windows em <paramref name="win32Error"/>
    /// (1314 = privilégio ausente). O código existe para o "não sei" ter motivo, em vez de ser engolido.
    /// </summary>
    public static uint? Query(AuditSubcategory subcategory, out int win32Error)
    {
        win32Error = 0;
        try
        {
            var guids = new[] { Guid.Parse(subcategory.Guid) };
            if (!AuditQuerySystemPolicy(guids, 1, out var buffer) || buffer == IntPtr.Zero)
            {
                win32Error = Marshal.GetLastWin32Error();
                return null;
            }
            try { return Marshal.PtrToStructure<AUDIT_POLICY_INFORMATION>(buffer).AuditingInformation; }
            finally { AuditFree(buffer); }
        }
        catch (Exception) { win32Error = -1; return null; }
    }

    /// <summary>Liga a auditoria de sucesso da subcategoria. Lança se o <c>auditpol</c> recusar.</summary>
    public static void EnableSuccess(AuditSubcategory subcategory) => NativeTool.Run("auditpol.exe", subcategory.EnableArguments);

    [StructLayout(LayoutKind.Sequential)]
    private struct AUDIT_POLICY_INFORMATION
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQuerySystemPolicy(
        [MarshalAs(UnmanagedType.LPArray)] Guid[] pSubCategoryGuids, uint dwPolicyCount, out IntPtr ppAuditPolicy);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);
}
