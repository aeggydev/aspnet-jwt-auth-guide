using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using jwt_blog.DTO;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(option =>
{
    option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter a valid token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });
    option.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] { }
        }
    });
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(opt =>
{
    opt.TokenValidationParameters = new()
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Secret"])),
        ValidateAudience = false,
        ValidateIssuer = false
    };
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/login", ([FromBody] Login login) =>
{
    var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Secret"]));
    var authClaims = new List<Claim>
    {
        new("sub", login.Username),
        new(ClaimTypes.Role, "User")
    };
    var token = new JwtSecurityToken(
        signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256),
        expires: DateTime.Now.AddDays(14),
        claims: authClaims);
    return new JwtSecurityTokenHandler().WriteToken(token);
});
app.MapGet("/test", [Authorize(Roles = "User")]() =>
{
    return "Hello World";
});

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapControllers();

app.Run();