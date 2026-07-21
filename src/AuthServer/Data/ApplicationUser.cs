using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace AuthServer.Data;

/// <summary>
/// 自訂的使用者類別，擴充事業群 (BG)、事業處 (BU) 與員工工號 (EMP_CD) 欄位
/// </summary>
public class ApplicationUser : IdentityUser
{
    [MaxLength(50)]
    public string? BG { get; set; }

    [MaxLength(50)]
    public string? BU { get; set; }

    [MaxLength(50)]
    public string? EMP_CD { get; set; }
}
