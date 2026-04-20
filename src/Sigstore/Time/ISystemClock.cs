namespace Sigstore.Time;

/// <summary>
/// Abstraction over wall-clock time so verification can be tested without calling
/// <see cref="DateTimeOffset"/> directly.
/// </summary>
public interface ISystemClock
{
    /// <summary>
    /// Returns the current UTC instant.
    /// </summary>
    /// <returns>Current time in UTC.</returns>
    DateTimeOffset UtcNow { get; }
}
