using System.Net.Http;
using System.Text.Json;
using Sigstore.Exceptions;

namespace Sigstore.Oidc;

/// <summary>
/// Obtains an OIDC token from the GitHub Actions runtime via
/// <c>ACTIONS_ID_TOKEN_REQUEST_URL</c> and <c>ACTIONS_ID_TOKEN_REQUEST_TOKEN</c>.
/// </summary>
public sealed class GitHubActionsTokenProvider : IOidcTokenProvider
{
    private readonly HttpClient _httpClient;

    /// <summary>Creates a provider backed by the given <paramref name="httpClient"/>.</summary>
    public GitHubActionsTokenProvider(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    /// <inheritdoc/>
    public bool IsAvailable =>
        !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL")) &&
        !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN"));

    /// <inheritdoc/>
    public async Task<string> GetTokenAsync(string audience, CancellationToken cancellationToken)
    {
        string? requestUrl = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL");
        string? bearerToken = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN");

        if (string.IsNullOrEmpty(requestUrl) || string.IsNullOrEmpty(bearerToken))
        {
            throw new OidcTokenException("GitHub Actions OIDC token provider is not available: ACTIONS_ID_TOKEN_REQUEST_URL or ACTIONS_ID_TOKEN_REQUEST_TOKEN is not set.");
        }

        string url = $"{requestUrl}&audience={Uri.EscapeDataString(audience)}";
        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearerToken);

        using HttpResponseMessage response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new OidcTokenException($"GitHub Actions OIDC token request failed (HTTP {(int)response.StatusCode}).");
        }

        string json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            string? value = doc.RootElement.GetProperty("value").GetString();
            if (string.IsNullOrEmpty(value))
            {
                throw new OidcTokenException("GitHub Actions OIDC token response did not contain a 'value' field.");
            }
            return value;
        }
        catch (System.Text.Json.JsonException ex)
        {
            throw new OidcTokenException("GitHub Actions OIDC token response is not valid JSON.", ex);
        }
        catch (System.Collections.Generic.KeyNotFoundException ex)
        {
            throw new OidcTokenException("GitHub Actions OIDC token response did not contain a 'value' field.", ex);
        }
    }
}
