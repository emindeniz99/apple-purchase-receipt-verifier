"""Replay the legacy receipt review with an existing Maven test build."""
import argparse
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser()
parser.add_argument("--repo", type=Path, required=True)
parser.add_argument("--jdk", type=Path, required=True)
parser.add_argument("--scratch", type=Path, required=True)
parser.add_argument("--security-only", action="store_true")
args = parser.parse_args()
repo = args.repo.resolve()
scratch = args.scratch.resolve()
if scratch.is_relative_to(repo):
    raise SystemExit("Use a scratch directory outside the repository.")
scratch.mkdir(parents=True, exist_ok=True)
classes = scratch / "classes"
inputs = scratch / "inputs"
classes.mkdir(exist_ok=True)
inputs.mkdir(exist_ok=True)
report = next((repo / "java/target/surefire-reports").glob("TEST-*.xml"))
properties = ET.parse(report).getroot().find("properties")
classpath = next(p.attrib["value"] for p in properties if p.attrib["name"] == "java.class.path")
source = repo / "docs/evidence/2026-10-14-java-legacy-temurin17-review/LegacyReviewProbe.java"
security = source.with_name("SecurityReviewProbe.java")
older = repo / "docs/evidence/2026-10-05-java-presignature-parse-cost/PresignatureCost.java"
subprocess.run([str(args.jdk / "bin/javac"), "-cp", classpath, "-d", str(classes), str(source), str(security), str(older)], check=True)
classpath = str(classes) + ":" + classpath
probe = "io.github.emindeniz99.applepurchasereceiptverifier.LegacyReviewProbe"

with (scratch / "results.txt").open("w") as output:
    def java(heap, main, *arguments, check=True):
        return subprocess.run(
            [str(args.jdk / "bin/java"), "-Xmx" + str(heap) + "m",
             "-Daprv.fixtures.dir=" + str(repo / "fixtures"), "-cp", classpath,
             main, *map(str, arguments)],
            cwd=repo, stdout=output, stderr=output, check=check,
        )

    security_probe = "io.github.emindeniz99.applepurchasereceiptverifier.SecurityReviewProbe"
    java(512, security_probe, "binding", repo / "fixtures/public-receipts")
    java(512, security_probe, "costs", repo / "fixtures/public-receipts", inputs)
    if args.security_only:
        print("Security review results written to the scratch directory.")
        raise SystemExit(0)
    java(512, probe, "acceptance", repo / "fixtures/public-receipts")
    java(1024, probe, "date-equivalence")
    java(1024, "PresignatureCost", "make", inputs)
    for name, roots in [
        ("baseline", inputs / "root.der"),
        ("tiny-attributes", "default"),
        ("tiny-attributes", inputs / "root.der"),
        ("unsigned-attribute", "default"),
    ]:
        output.write(f"{name}, trusted test root={roots != 'default'}\n")
        output.flush()
        java(1024, "PresignatureCost", "measure", inputs / (name + ".b64"), roots)
    for name in ["receipt-sandbox-legacy", "receipt-sandbox-g5"]:
        output.write(name + "\n")
        output.flush()
        java(512, "PresignatureCost", "measure", repo / "fixtures/public-receipts" / (name + ".b64"), "default")
    java(1024, probe, "date-cost", inputs / "tiny-attributes.b64")
    for heap in [64, 128]:
        output.write(f"forged tiny attributes, heap {heap} MiB\n")
        output.flush()
        result = java(heap, "PresignatureCost", "once", inputs / "tiny-attributes.b64", "default", check=False)
        output.write(f"exit {result.returncode}\n")
print("Review results written to the scratch directory.")
