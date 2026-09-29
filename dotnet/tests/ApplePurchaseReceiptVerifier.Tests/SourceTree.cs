using System;
using System.Collections.Generic;
using System.IO;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>Finds the library's own source files, for the tests that look at what the library is allowed to contain.</summary>
internal static class SourceTree
{
    /// <summary>Every <c>.cs</c> file of the library project, outside <c>bin</c> and <c>obj</c>.</summary>
    internal static IEnumerable<string> LibraryFiles()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, "dotnet", "src", "ApplePurchaseReceiptVerifier");
            if (Directory.Exists(candidate))
            {
                foreach (string file in Directory.GetFiles(candidate, "*.cs", SearchOption.AllDirectories))
                {
                    string relative = file.Substring(candidate.Length);
                    if (!relative.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                        && !relative.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                    {
                        yield return file;
                    }
                }

                yield break;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("could not locate the library sources");
    }
}
