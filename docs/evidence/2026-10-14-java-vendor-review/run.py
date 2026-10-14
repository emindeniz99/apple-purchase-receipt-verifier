#!/usr/bin/env python3
"""Run the Java-only review with all outputs outside the source checkout."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser()
parser.add_argument("--repo", type=Path, required=True)
parser.add_argument("--scratch", type=Path, required=True)
parser.add_argument("--jdk", type=Path, required=True)
parser.add_argument("--maven", type=Path, required=True)
parser.add_argument("--build-only", action="store_true")
parser.add_argument("--probe-only", action="store_true")
args = parser.parse_args()
repo, scratch = args.repo.resolve(), args.scratch.resolve()
if scratch == repo or repo in scratch.parents:
    raise SystemExit("Scratch must be outside the repository.")
scratch.mkdir(parents=True, exist_ok=True)
checkout = scratch / "checkout"
env = os.environ.copy()
env["JAVA_HOME"] = str(args.jdk.resolve())
env["PATH"] = str(args.jdk.resolve() / "bin") + os.pathsep + env["PATH"]
env["MAVEN_OPTS"] = "-Xmx1024m " + env.get("MAVEN_OPTS", "")
env["MAVEN_ARGS"] = "-Dmaven.repo.local=" + str(scratch / "m2")
proxy_url = env.get("HTTPS_PROXY") or env.get("HTTP_PROXY")
if proxy_url:
    proxy = urlparse(proxy_url)
    if proxy.username or proxy.password:
        raise SystemExit("Use a preconfigured Maven settings file for an authenticated proxy.")
    settings = scratch / "maven-settings.xml"
    settings.write_text(
        '<settings><proxies><proxy><id>review</id><active>true</active>'
        '<protocol>http</protocol><host>' + proxy.hostname + '</host><port>'
        + str(proxy.port or 80) + '</port></proxy></proxies></settings>')
    env["MAVEN_ARGS"] += " -s " + str(settings)

def execute(command, name, cwd=checkout):
    with (scratch / name).open("w") as log:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=log)
    print(name + ": exit " + str(result.returncode), flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)

if not args.probe_only:
    for directory in ("java", "fixtures", "certs"):
        shutil.copytree(repo / directory, checkout / directory,
                        ignore=shutil.ignore_patterns("target"), dirs_exist_ok=True)
    execute([str(args.jdk / "bin/java"), "-version"], "java-version.log")
    execute([str(args.maven), "-version"], "maven-version.log")
    execute([str(args.maven), "-B", "-f", "java/pom.xml", "verify"], "verify.log")
    totals = dict(tests=0, failures=0, errors=0, skipped=0)
    for report in (checkout / "java/target/surefire-reports").glob("TEST-*.xml"):
        suite = ET.parse(report).getroot()
        for key in totals:
            totals[key] += int(suite.attrib[key])
    (scratch / "suite-summary.json").write_text(json.dumps(totals, indent=2) + "\n")
    print(json.dumps(totals), flush=True)
if args.build_only:
    raise SystemExit(0)

report = next((checkout / "java/target/surefire-reports").glob("TEST-*.xml"))
properties = ET.parse(report).getroot().find("properties")
classpath = next(p.attrib["value"] for p in properties if p.attrib["name"] == "java.class.path")
classes = scratch / "probe-classes"
classes.mkdir(exist_ok=True)
source = repo / "docs/evidence/2026-10-14-java-vendor-review/VendorReviewProbe.java"
execute([str(args.jdk / "bin/javac"), "--release", "8", "-cp", classpath,
         "-d", str(classes), str(source)], "probe-compile.log")
execute([str(args.jdk / "bin/java"), "-Xmx512m", "-cp", str(classes) + os.pathsep + classpath,
         "io.github.emindeniz99.applepurchasereceiptverifier.VendorReviewProbe",
         str(checkout / "fixtures/public-receipts")], "probe.log")
