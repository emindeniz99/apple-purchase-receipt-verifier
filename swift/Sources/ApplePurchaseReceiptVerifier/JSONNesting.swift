/// Whether `bytes`, read as JSON text, opens more than `limit` arrays and
/// objects at once. Brackets inside string literals are data, not nesting,
/// so strings and their backslash escapes are skipped.
///
/// Run before `JSONSerialization` and `JSONDecoder`, which take no depth
/// option and recurse once per level: the bound is decided by this linear
/// scan, not by how deep the parser's stack happens to reach. Only the
/// bracket count is judged; anything else malformed is left to the parser.
/// A close bracket with nothing open drives the count below zero, and the
/// parser stops at that bracket before it reaches whatever comes after.
func jsonNestingExceeds(_ bytes: some Sequence<UInt8>, limit: Int) -> Bool {
    var depth = 0
    var inString = false
    var escaped = false
    for byte in bytes {
        if inString {
            if escaped {
                escaped = false
            } else if byte == 0x5C {  // '\'
                escaped = true
            } else if byte == 0x22 {  // '"'
                inString = false
            }
            continue
        }
        switch byte {
        case 0x22:  // '"'
            inString = true
        case 0x5B, 0x7B:  // '[' '{'
            depth += 1
            if depth > limit { return true }
        case 0x5D, 0x7D:  // ']' '}'
            depth -= 1
        default:
            break
        }
    }
    return false
}
