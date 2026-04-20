namespace Sigstore.Time;

/// <summary>
/// Default <see cref="ISystemClock"/> implementation backed by <see cref="DateTimeOffset.UtcNow"/>.
/// </summary>
public sealed class DefaultSystemClock : ISystemClock
{
    /// <inheritdoc />
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
