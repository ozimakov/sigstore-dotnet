namespace Sigstore.Conformance;


/// <summary>
/// Tool entrypoint for the Sigstore conformance suite.
/// </summary>
public static class Program
{
    /// <summary>
    /// Application entrypoint.
    /// </summary>
    /// <param name="args">Process arguments.</param>
    /// <returns>Exit code.</returns>
    public static async Task<int> Main(string[] args)
    {
        return await ConformanceRunner.RunAsync(args).ConfigureAwait(false);
    }
}
