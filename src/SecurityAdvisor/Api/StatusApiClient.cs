using System.Net.Http.Headers;
using System.Text.Json;
using SecurityAgent.StatusContract;

namespace SecurityAdvisor.Api;

public sealed record ApiResult<T>(bool Ok, T? Value, int StatusCode, string? Error)
{
    public bool NotFound => StatusCode == 404;
}

/// <summary>
/// Único canal del sistema 2 hacia el sistema 1 (principios 10 y 11). Solo emite peticiones GET a la API de estado:
/// no existe ningún método que envíe otro verbo, y ningún tipo de este ensamblado conoce la base de datos ni el firewall.
/// </summary>
public sealed class StatusApiClient
{
    private readonly HttpClient _http;

    public StatusApiClient(HttpClient http, string baseUrl, string token)
    {
        _http = http;
        _http.BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/");
        _http.Timeout = TimeSpan.FromSeconds(20);
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    public Task<ApiResult<StatusDto>> GetStatusAsync(CancellationToken ct = default) => GetAsync<StatusDto>("api/v1/status", ct);

    public Task<ApiResult<ListDto<AlertDto>>> ListAlertsAsync(string? rule, string? severity, string? ip, string? since, int? limit, CancellationToken ct = default)
    {
        var q = new List<string>();
        void Add(string k, string? v) { if (!string.IsNullOrWhiteSpace(v)) q.Add($"{k}={Uri.EscapeDataString(v)}"); }
        Add("rule", rule); Add("severity", severity); Add("ip", ip); Add("since", since);
        if (limit is > 0) q.Add($"limit={limit}");
        return GetAsync<ListDto<AlertDto>>("api/v1/alerts" + (q.Count > 0 ? "?" + string.Join("&", q) : ""), ct);
    }

    public Task<ApiResult<ListDto<BlockDto>>> ListBlocksAsync(CancellationToken ct = default) => GetAsync<ListDto<BlockDto>>("api/v1/blocks", ct);

    public Task<ApiResult<RuleDetailDto>> GetRuleAsync(string id, CancellationToken ct = default) =>
        GetAsync<RuleDetailDto>("api/v1/rules/" + Uri.EscapeDataString(id), ct);

    public Task<ApiResult<AuditSummaryDto>> GetAuditSummaryAsync(CancellationToken ct = default) => GetAsync<AuditSummaryDto>("api/v1/audit", ct);

    public Task<ApiResult<EventDetailDto>> GetEventAsync(string id, CancellationToken ct = default) =>
        GetAsync<EventDetailDto>("api/v1/events/" + Uri.EscapeDataString(id), ct);

    private async Task<ApiResult<T>> GetAsync<T>(string path, CancellationToken ct)
    {
        try
        {
            using var resp = await _http.GetAsync(path, ct);
            var body = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode)
                return new ApiResult<T>(false, default, (int)resp.StatusCode, resp.StatusCode switch
                {
                    System.Net.HttpStatusCode.NotFound => "no encontrado",
                    System.Net.HttpStatusCode.Unauthorized => "token rechazado por la API de estado",
                    System.Net.HttpStatusCode.Forbidden => "cliente no permitido por la API de estado",
                    System.Net.HttpStatusCode.BadRequest => "parámetros inválidos",
                    _ => $"error {(int)resp.StatusCode} de la API de estado"
                });
            var value = JsonSerializer.Deserialize<T>(body, StatusJson.Options);
            return value is null ? new ApiResult<T>(false, default, (int)resp.StatusCode, "respuesta vacía") : new ApiResult<T>(true, value, (int)resp.StatusCode, null);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            return new ApiResult<T>(false, default, 0, "la API de estado no responde");
        }
    }
}
