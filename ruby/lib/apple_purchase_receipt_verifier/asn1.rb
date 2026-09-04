# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # Bounded BER/DER handling for attacker-supplied bytes.
  #
  # Why this exists rather than `OpenSSL::ASN1.decode`: that decoder recurses
  # in C and, on deeply nested input, raises `SystemStackError` — which is not
  # a `StandardError`, so it walks straight through `rescue => e`. Measured on
  # ruby 3.3.6: 100_000 nested definite-length SEQUENCEs (~400 KB) and 500_000
  # nested indefinite-length ones (~2 MB) both escape in under 20 ms.
  #
  # So every byte string this library receives from the outside is first run
  # through {Asn1.scan!}, an iterative explicit-stack pass with no Ruby
  # recursion at all. Only once the input is proven shallow, node-bounded and
  # fully consumed does anything else — {Asn1.parse}, `OpenSSL::PKCS7.new`,
  # `OpenSSL::X509::Certificate.new` — get to see it.
  module Asn1
    # Structural defect in the bytes. Callers map it onto a Reason; it never
    # escapes the library.
    class Error < StandardError; end

    # Apple's deepest genuine structure is about 8 levels. 32 leaves room for
    # anything real while keeping the recursive tree builder below far from
    # Ruby's stack limit.
    MAX_DEPTH = 32

    # A ceiling on how much work one blob can ask for. The 79 KB / 187-purchase
    # legacy receipt — the largest genuine input known to this project — scans
    # to roughly 6_000 nodes.
    MAX_NODES = 200_000

    TAG_INTEGER          = 0x02
    TAG_OCTET_STRING     = 0x04
    TAG_OID              = 0x06
    TAG_UTF8_STRING      = 0x0C
    TAG_IA5_STRING       = 0x16
    TAG_SEQUENCE         = 0x30
    TAG_SET              = 0x31
    TAG_CONTEXT_0        = 0xA0
    TAG_OCTET_STRING_BER = 0x24 # constructed OCTET STRING (BER)

    class << self
      # Validates the structure of exactly one outermost TLV covering the whole
      # buffer. Raises {Error} on: trailing bytes, truncation, nesting past
      # {MAX_DEPTH}, more than {MAX_NODES} nodes, multi-byte tags, length octets
      # longer than four bytes, indefinite length on a primitive, a child
      # overrunning its parent, an unterminated indefinite container, or an
      # end-of-contents marker with nothing open.
      #
      # Iterative by construction: the only state is an explicit array of open
      # container ends. A recursive spelling of this method was measured to
      # spend 28 seconds and then raise `SystemStackError` on the same input
      # this one rejects in 0.06 ms.
      #
      # @return [Integer] the number of TLV nodes seen
      def scan!(bytes)
        size = bytes.bytesize
        raise Error, "empty input" if size.zero?

        stack = [] # Integer end offset for definite containers, :indefinite otherwise
        off = 0
        nodes = 0
        top_level_values = 0

        loop do
          while !stack.empty? && stack.last.is_a?(Integer) && stack.last <= off
            raise Error, "child overruns its parent" if stack.last < off

            stack.pop
          end
          break if stack.empty? && off >= size
          raise Error, "truncated ASN.1 value" if off + 2 > size

          first = bytes.getbyte(off)
          if first.zero? && bytes.getbyte(off + 1).zero?
            raise Error, "end-of-contents with no open indefinite value" if stack.last != :indefinite

            stack.pop
            off += 2
            next
          end

          raise Error, "multi-byte ASN.1 tags are not supported" if (first & 0x1F) == 0x1F

          constructed = (first & 0x20) != 0
          pos = off + 1
          length_byte = bytes.getbyte(pos)
          pos += 1
          if length_byte < 0x80
            length = length_byte
          elsif length_byte == 0x80
            raise Error, "indefinite length on a primitive value" unless constructed

            length = nil
          else
            count = length_byte & 0x7F
            raise Error, "unsupported ASN.1 length (#{count} octets)" if count > 4
            raise Error, "truncated ASN.1 length" if pos + count > size

            length = 0
            count.times do
              length = (length << 8) | bytes.getbyte(pos)
              pos += 1
            end
          end

          nodes += 1
          raise Error, "ASN.1 node budget exceeded" if nodes > MAX_NODES

          if stack.empty?
            top_level_values += 1
            raise Error, "trailing bytes after the outermost ASN.1 value" if top_level_values > 1
          end

          if length.nil?
            raise Error, "ASN.1 nesting too deep" if stack.size >= MAX_DEPTH

            stack.push(:indefinite)
            off = pos
          else
            content_end = pos + length
            raise Error, "ASN.1 length exceeds the input" if content_end > size

            parent = stack.last
            raise Error, "child overruns its parent" if parent.is_a?(Integer) && content_end > parent

            if constructed
              raise Error, "ASN.1 nesting too deep" if stack.size >= MAX_DEPTH

              stack.push(content_end)
              off = pos
            else
              off = content_end
            end
          end
        end

        raise Error, "unterminated indefinite-length value" unless stack.empty?
        raise Error, "trailing bytes after the outermost ASN.1 value (#{size - off})" if off != size
        raise Error, "no ASN.1 value" if top_level_values.zero?

        nodes
      end

      # Reads exactly one definite-length TLV that spans the whole buffer and
      # returns its tag and value bytes, without descending into it and without
      # any recursion. This is what the receipt attribute reader uses for
      # attribute *values*, which are always a single primitive: it is both
      # stricter than a general parse (a constructed or indefinite value in
      # that position is rejected outright) and enough faster to matter, since
      # a 187-purchase receipt asks for about two thousand of them.
      #
      # @return [Array(Integer, String)] tag byte and value bytes
      def read_single(bytes)
        size = bytes.bytesize
        raise Error, "truncated ASN.1 value" if size < 2

        tag = bytes.getbyte(0)
        raise Error, "multi-byte ASN.1 tags are not supported" if (tag & 0x1F) == 0x1F

        pos = 1
        length_byte = bytes.getbyte(pos)
        pos += 1
        if length_byte == 0x80
          raise Error, "indefinite length where a single value was expected"
        elsif length_byte < 0x80
          length = length_byte
        else
          count = length_byte & 0x7F
          raise Error, "unsupported ASN.1 length (#{count} octets)" if count > 4
          raise Error, "truncated ASN.1 length" if pos + count > size

          length = 0
          count.times do
            length = (length << 8) | bytes.getbyte(pos)
            pos += 1
          end
        end

        raise Error, "ASN.1 length exceeds the input" if pos + length > size
        raise Error, "trailing bytes after the outermost ASN.1 value" if pos + length != size

        [tag, bytes.byteslice(pos, length)]
      end

      # Builds a node tree for bytes that have already passed {scan!}. Depth is
      # therefore bounded by {MAX_DEPTH} and the recursion below cannot run
      # away. Nodes carry offsets, not slices: the 187-purchase receipt makes
      # about 8_500 of them and copying each one's bytes is the difference
      # between a few milliseconds and tens of them.
      # `depth_limit` stops the builder from expanding the children of nodes at
      # that depth: a certificate set can then be enumerated for its members'
      # raw bytes without every certificate's internals being turned into
      # objects first. Indefinite-length values are always expanded, because
      # finding their end-of-contents marker is what determines where they end.
      def parse(bytes, depth_limit: MAX_DEPTH)
        scan!(bytes)
        node, = read_node(bytes, 0, bytes.bytesize, 0, depth_limit)
        node
      end

      # Parses bytes already known to be structurally sound, without
      # re-scanning. Only for buffers carved out of an already-scanned parent.
      def parse_scanned(bytes, depth_limit: MAX_DEPTH)
        node, = read_node(bytes, 0, bytes.bytesize, 0, depth_limit)
        node
      end

      private

      def read_node(bytes, off, limit, depth, depth_limit)
        raise Error, "ASN.1 nesting too deep" if depth > MAX_DEPTH
        raise Error, "truncated ASN.1 value" if off + 2 > limit

        tag = bytes.getbyte(off)
        constructed = (tag & 0x20) != 0
        pos = off + 1
        length_byte = bytes.getbyte(pos)
        pos += 1
        if length_byte < 0x80
          length = length_byte
        elsif length_byte == 0x80
          length = nil
        else
          count = length_byte & 0x7F
          length = 0
          count.times do
            length = (length << 8) | bytes.getbyte(pos)
            pos += 1
          end
        end

        if length.nil?
          children = []
          while pos + 2 <= limit
            break if bytes.getbyte(pos).zero? && bytes.getbyte(pos + 1).zero?

            child, pos = read_node(bytes, pos, limit, depth + 1, depth_limit)
            children << child
          end
          node_end = pos + 2
          return [Node.new(bytes, tag, true, off, node_end, pos, pos, children), node_end]
        end

        content_end = pos + length
        children = nil
        if constructed && depth < depth_limit
          children = []
          cursor = pos
          while cursor < content_end
            child, cursor = read_node(bytes, cursor, content_end, depth + 1, depth_limit)
            children << child
          end
        end
        [Node.new(bytes, tag, constructed, off, content_end, pos, content_end, children), content_end]
      end
    end

    # One ASN.1 value, expressed as offsets into the buffer it was read from.
    Node = Struct.new(:buffer, :tag, :constructed, :start, :finish, :content_start, :content_end,
                      :children) do
      # The complete TLV bytes.
      def raw
        buffer.byteslice(start, finish - start)
      end

      # The value bytes. For an indefinite-length constructed value this is
      # empty; use {#octet_value} for BER-chunked OCTET STRINGs.
      def content
        buffer.byteslice(content_start, content_end - content_start)
      end

      def content_length
        content_end - content_start
      end

      def kids
        children || []
      end

      def octet_string?
        [TAG_OCTET_STRING, TAG_OCTET_STRING_BER].include?(tag)
      end

      # Value bytes of an OCTET STRING, joining BER constructed chunks.
      def octet_value
        return content unless constructed

        kids.map(&:octet_value).join
      end
    end
  end
end
