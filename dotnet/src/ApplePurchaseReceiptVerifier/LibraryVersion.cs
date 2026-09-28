namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// This library's own version, for startup logs. Corresponds to the
    /// design's <c>Version.CURRENT</c>; named <c>LibraryVersion</c> rather than
    /// <c>Version</c> so an unqualified <c>Version</c> in a consumer's file
    /// keeps resolving to <see cref="System.Version"/>.
    /// </summary>
    /// <remarks>
    /// Bumped by release-please, the same as <c>dotnet/Directory.Build.props</c>'
    /// <c>&lt;Version&gt;</c> element: this file needs its own entry in the
    /// repository root's <c>release-please-config.json</c> <c>extra-files</c>
    /// list (a <c>generic</c> strategy entry matching the
    /// <c>x-release-please-version</c> marker below) so a future release bumps
    /// both in the same commit. Until that entry exists, keep this in step with
    /// <c>Directory.Build.props</c> by hand.
    /// </remarks>
    public static class LibraryVersion
    {
        /// <summary>The current released version, e.g. <c>"0.7.0"</c>.</summary>
        public const string Current = "0.7.0"; // x-release-please-version
    }
}
