using Microsoft.AspNetCore.Authentication.Cookies;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options => {
        //AddingAuthentication
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/denied";
    });
builder.Services.AddAuthorization(options =>
{
    //policy based role check
    options.AddPolicy("RequireHRRole", policy => policy.RequireRole("HR"));
    //AddingClaimChecks
    options.AddPolicy("EmployeeOnly", policy => policy.RequireClaim("EmployeeNumber"));
});
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthorization();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.Run();