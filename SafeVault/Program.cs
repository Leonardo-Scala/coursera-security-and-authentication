using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Security;
using SafeVault.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();

// Database configuration
builder.Services.AddDbContext<SafeVaultDbContext>(options =>
{
    // Use In-Memory database for testing/development
    options.UseInMemoryDatabase("SafeVaultDb");
    
    // For production, use SQL Server:
    // options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

// JWT Configuration
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = builder.Configuration["JwtSettings:SecretKey"] ?? "SafeVault_Super_Secret_Key_That_Should_Be_Changed_In_Production_2024!";
var issuer = builder.Configuration["JwtSettings:Issuer"] ?? "SafeVault";
var audience = builder.Configuration["JwtSettings:Audience"] ?? "SafeVault-Users";

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = issuer,
        ValidAudience = audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
        ClockSkew = TimeSpan.Zero
    };

    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogWarning("Authentication failed: {Exception}", context.Exception.Message);
            return Task.CompletedTask;
        },
        OnChallenge = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogWarning("Authentication challenge: {Error}", context.Error);
            return Task.CompletedTask;
        }
    };
});

// Authorization policies
builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();

    options.AddPolicy("RequireUser", policy =>
        policy.RequireRole("User", "Admin", "SuperAdmin"));

    options.AddPolicy("RequireAdmin", policy =>
        policy.RequireRole("Admin", "SuperAdmin"));

    options.AddPolicy("RequireSuperAdmin", policy =>
        policy.RequireRole("SuperAdmin"));

    options.AddPolicy("ResourceOwner", policy =>
        policy.Requirements.Add(new ResourceOwnerRequirement()));
});

// Register custom services
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<IAuthorizationHandler, ResourceOwnerHandler>();

// Add CORS for development
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// Add HTTP context accessor for authorization handlers
builder.Services.AddHttpContextAccessor();

// Add anti-forgery tokens
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "SafeVault-CSRF";
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});

// Add API versioning and documentation
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { 
        Title = "SafeVault API", 
        Version = "v1",
        Description = "A secure vault application with robust authentication and authorization"
    });

    // Add JWT authentication to Swagger
    c.AddSecurityDefinition("Bearer", new()
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "JWT Authorization header using the Bearer scheme."
    });

    c.AddSecurityRequirement(new()
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Logging configuration
builder.Services.AddLogging(logging =>
{
    logging.AddConsole();
    logging.AddDebug();
    logging.SetMinimumLevel(LogLevel.Information);
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
    app.UseCors("AllowAll");
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Content-Security-Policy", 
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
    
    await next();
});

app.UseHttpsRedirection();

// Authentication and Authorization
app.UseAuthentication();
app.UseAuthorization();

// Anti-forgery token for forms
app.UseAntiforgery();

app.MapControllers();

// Initialize database with seed data
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<SafeVaultDbContext>();
    await context.Database.EnsureCreatedAsync();

    // Log initialization
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
    logger.LogInformation("SafeVault application initialized with authentication and authorization");
    logger.LogInformation("Default admin user: admin@safevault.com / Admin123!");
    logger.LogInformation("Default test user: user@safevault.com / User123!");
}

// Health check endpoint
app.MapGet("/health", () => Results.Ok(new 
{ 
    status = "healthy", 
    timestamp = DateTime.UtcNow,
    version = "1.0.0",
    environment = app.Environment.EnvironmentName
}));

// Welcome endpoint
app.MapGet("/", () => Results.Ok(new 
{ 
    message = "Welcome to SafeVault API",
    version = "1.0.0",
    documentation = "/swagger",
    authentication = "JWT Bearer Token required for most endpoints",
    defaultAccounts = new 
    {
        admin = new { email = "admin@safevault.com", username = "admin", role = "SuperAdmin" },
        user = new { email = "user@safevault.com", username = "testuser", role = "User" }
    }
}));

app.Run();
