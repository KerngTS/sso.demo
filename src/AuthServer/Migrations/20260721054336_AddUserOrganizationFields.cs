using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthServer.Migrations
{
    /// <inheritdoc />
    public partial class AddUserOrganizationFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "BG",
                table: "AspNetUsers",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "BU",
                table: "AspNetUsers",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "EMP_CD",
                table: "AspNetUsers",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "BG",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "BU",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "EMP_CD",
                table: "AspNetUsers");
        }
    }
}
