using System.Security.Cryptography;
using System.Text;
using JwtAuthApi.Data;
using JwtAuthApi.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Configure database connection
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure JWT Authentication
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var key = Encoding.UTF8.GetBytes(jwtSettings["Key"] ?? throw new InvalidOperationException("JWT Key is missing from configuration."));

builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key)
        };
    });

// Add authorization service
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Endpoint para registrar un nuevo usuario
app.MapPost("/register", async (AppDbContext dbContext, User newUser) =>
{
    if (await dbContext.Users.AnyAsync(u => u.Email == newUser.Email))
    {
        return Results.Conflict("El usuario con este correo ya está registrado.");
    }

    using var sha256 = SHA256.Create();
    var passwordHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(newUser.PasswordHash));
    newUser.PasswordHash = Convert.ToBase64String(passwordHash);

    dbContext.Users.Add(newUser);
    await dbContext.SaveChangesAsync();

    return Results.Created($"/users/{newUser.Id}", newUser);
});

// Endpoint para login y generación de JWT
app.MapPost("/login", async (AppDbContext dbContext, LoginRequest loginRequest) =>
{
    var user = await dbContext.Users.SingleOrDefaultAsync(u => u.Email == loginRequest.Email);
    if (user == null) return Results.NotFound("Usuario no encontrado.");

    using var sha256 = SHA256.Create();
    var passwordHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(loginRequest.PasswordHash));
    var hashedPassword = Convert.ToBase64String(passwordHash);

    if (user.PasswordHash != hashedPassword)
        return Results.Json(new { message = "Contraseña incorrecta" }, statusCode: 401);

    var jwtToken = GenerateJwtToken(user);
    return Results.Ok(new { Token = jwtToken });
});


// Function to generate a JWT
string GenerateJwtToken(User user)
{
    var keyString = jwtSettings["Key"] ?? throw new InvalidOperationException("JWT Key is missing from configuration.");
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyString));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, user.Email)
    };

    var token = new JwtSecurityToken(
        issuer: jwtSettings["Issuer"],
        audience: jwtSettings["Audience"],
        claims: claims,
        expires: DateTime.UtcNow.AddHours(1),
        signingCredentials: creds
    );

    return new JwtSecurityTokenHandler().WriteToken(token);
}


// Endpoint protegido para ver el perfil del usuario autenticado
app.MapGet("/secure/profile", async (AppDbContext dbContext, HttpContext httpContext) =>
{
    var email = httpContext.User.Identity?.Name;
    if (string.IsNullOrEmpty(email)) return Results.Unauthorized();

    var user = await dbContext.Users.SingleOrDefaultAsync(u => u.Email == email);
    if (user == null) return Results.NotFound("Usuario no encontrado.");

    return Results.Ok(user);
}).RequireAuthorization();

app.Run();
