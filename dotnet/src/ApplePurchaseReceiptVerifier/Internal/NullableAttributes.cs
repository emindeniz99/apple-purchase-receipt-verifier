#if NETSTANDARD2_0
namespace System.Diagnostics.CodeAnalysis
{
    /// <summary>
    /// The compiler's nullable flow attribute, which netstandard2.0 does not
    /// ship. The compiler matches it by name, so this internal copy gives a
    /// netstandard2.0 consumer the same flow analysis as a net8.0 one.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Property, Inherited = false, AllowMultiple = true)]
    internal sealed class MemberNotNullWhenAttribute : Attribute
    {
        public MemberNotNullWhenAttribute(bool returnValue, string member)
        {
            ReturnValue = returnValue;
            Members = new[] { member };
        }

        public bool ReturnValue { get; }

        public string[] Members { get; }
    }
}
#endif
