import sys, json, os, time
sys.path.insert(0, os.path.dirname(__file__))
from scanner import ScannerEngine, BatchScanner

PROGRESS_INTERVAL = 0.5

def report(obj):
    print(json.dumps(obj), flush=True)

def progress_callback(completed, total, current_path):
    report({"type": "progress", "completed": completed, "total": total, "path": current_path})

def main():
    if not sys.argv[1:]:
        report([])
        return

    paths = sys.argv[1:]
    engine = ScannerEngine()
    scanner = BatchScanner(engine)

    results = scanner.scan_paths(paths, progress_callback=progress_callback)

    for r in results:
        report({
            "type": "result",
            "path": r.path,
            "filename": r.filename,
            "size": r.size,
            "md5": r.md5,
            "sha256": r.sha256,
            "maxSeverity": r.max_severity.value,
            "findings": [
                {
                    "engine": f.engine,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                }
                for f in r.findings
            ],
        })

    report({"type": "done"})

if __name__ == "__main__":
    main()
