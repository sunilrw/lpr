// ==============================================================================
// 🟪 2. .NET / C# SDK INTEGRATION (CLI Process & HTTP REST Client)
// ==============================================================================
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;

public sealed class LprClient
{
    private readonly string _executablePath;
    private readonly HttpClient _http;
    private readonly string _apiBaseUrl;

    public LprClient(string executablePath = "lpr.exe", string apiBaseUrl = "http://127.0.0.1:8080")
    {
        _executablePath = executablePath;
        _apiBaseUrl = apiBaseUrl.TrimEnd('/');
        _http = new HttpClient();
    }

    // Option A: Execute standalone lpr.exe process and deserialize JSON rows directly
    public async Task<List<Dictionary<string, object>>> QueryCliAsync(string sql, string? file = null)
    {
        var psi = new ProcessStartInfo(_executablePath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-q");
        psi.ArgumentList.Add("-o");
        psi.ArgumentList.Add("json");
        if (!string.IsNullOrEmpty(file)) { psi.ArgumentList.Add("-f"); psi.ArgumentList.Add(file); }
        psi.ArgumentList.Add(sql);

        using var proc = Process.Start(psi)!;
        string stdout = await proc.StandardOutput.ReadToEndAsync();
        string stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        if (proc.ExitCode != 0) throw new InvalidOperationException($"lpr failed: {stderr}");
        return JsonSerializer.Deserialize<List<Dictionary<string, object>>>(stdout) ?? new();
    }

    // Option B: Query lpr HTTP REST API (`lpr serve`)
    public async Task<JsonElement> QueryRestApiAsync(string sql, string? source = null, string? format = null)
    {
        var response = await _http.PostAsJsonAsync($"{_apiBaseUrl}/v1/query", new { sql, source, format });
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }
}

