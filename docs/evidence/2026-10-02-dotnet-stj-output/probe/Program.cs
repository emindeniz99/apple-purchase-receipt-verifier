using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
string[] inputs = { "<script>&'+`", "\u007f\u0080\u00ad", "\u2028\u2029", "\ue000\ufeff\ufffe\uffff", "\u0378\u0870", "caf\u00e9 \U0001F600 \U0010FFFF", "\u0000\u001f", "\ud800 a\udc00b" };
foreach (var enc in new[] { ("default", JavaScriptEncoder.Default), ("relaxed", JavaScriptEncoder.UnsafeRelaxedJsonEscaping) })
foreach (string s in inputs)
{
    var ms = new MemoryStream();
    using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Encoder = enc.Item2 })) w.WriteStringValue(s);
    string outp = Encoding.UTF8.GetString(ms.ToArray());
    Console.WriteLine($"{Environment.Version} {enc.Item1}: {string.Concat(outp.Select(c => c < 0x20 || c > 0x7e ? $"<{(int)c:x4}>" : c.ToString()))}");
}
