using Microsoft.EntityFrameworkCore;
using SafeVault.Models;

namespace SafeVault.Data
{
    public class SafeVaultDbContext : DbContext
    {
        public SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure User entity
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.UserID);
                entity.HasIndex(e => e.Username).IsUnique();
                entity.HasIndex(e => e.Email).IsUnique();
                entity.Property(e => e.Username).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Email).IsRequired().HasMaxLength(255);
                entity.Property(e => e.PasswordHash).IsRequired();
                entity.Property(e => e.Role).IsRequired().HasMaxLength(50).HasDefaultValue("User");
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.IsActive).HasDefaultValue(true);

                // Configure relationships
                entity.HasMany(e => e.Sessions)
                      .WithOne(e => e.User)
                      .HasForeignKey(e => e.UserID)
                      .OnDelete(DeleteBehavior.Cascade);

                entity.HasMany(e => e.AuditLogs)
                      .WithOne(e => e.User)
                      .HasForeignKey(e => e.UserID)
                      .OnDelete(DeleteBehavior.SetNull);
            });

            // Configure UserSession entity
            modelBuilder.Entity<UserSession>(entity =>
            {
                entity.HasKey(e => e.SessionID);
                entity.HasIndex(e => e.SessionToken).IsUnique();
                entity.Property(e => e.SessionToken).IsRequired().HasMaxLength(500);
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.IPAddress).HasMaxLength(45); // IPv6 support
                entity.Property(e => e.UserAgent).HasMaxLength(500);
                entity.Property(e => e.IsActive).HasDefaultValue(true);
            });

            // Configure AuditLog entity
            modelBuilder.Entity<AuditLog>(entity =>
            {
                entity.HasKey(e => e.AuditID);
                entity.Property(e => e.Action).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Resource).IsRequired().HasMaxLength(200);
                entity.Property(e => e.Timestamp).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.IPAddress).HasMaxLength(45);
                entity.Property(e => e.Details).HasMaxLength(1000);
            });

            // Seed default admin user (for development/testing)
            SeedData(modelBuilder);
        }

        private void SeedData(ModelBuilder modelBuilder)
        {
            // Create default admin user
            var adminUser = new User
            {
                UserID = 1,
                Username = "admin",
                Email = "admin@safevault.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin123!", workFactor: 12),
                Role = "SuperAdmin",
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            var regularUser = new User
            {
                UserID = 2,
                Username = "testuser",
                Email = "user@safevault.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("User123!", workFactor: 12),
                Role = "User",
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            modelBuilder.Entity<User>().HasData(adminUser, regularUser);
        }
    }
}