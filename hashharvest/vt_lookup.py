"""VirusTotal hash reputation lookup.

Optional feature: requires the ``vt-py`` package (``pip install vt-py``) and a
VirusTotal API key. Imported lazily so the rest of HashHarvest runs without it.
- https://github.com/VirusTotal/vt-py
- Added ib 7/18/2026
"""


def verdict_from_stats(stats):
    """Reduce VirusTotal ``last_analysis_stats`` to a (verdict, detail) pair.

    Args:
        stats: Dict like ``{"malicious": 5, "harmless": 60, "undetected": 7, ...}``.

    Returns:
        ``(verdict, detail)`` where verdict is one of ``"malicious"``,
        ``"suspicious"``, or ``"clean"`` and detail is a ``"hits/total"`` string.
    """
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())
    if malicious:
        return "malicious", "%d/%d" % (malicious, total)
    if suspicious:
        return "suspicious", "%d/%d" % (suspicious, total)
    return "clean", "0/%d" % total


def lookup_hashes(api_key, hashes, progress_callback=None, result_callback=None):
    """Look up each hash on VirusTotal.

    Args:
        api_key: VirusTotal API key.
        hashes: Iterable of hash strings (deduplicated internally).
        progress_callback: Optional callable receiving an integer percentage.
        result_callback: Optional callable receiving ``(hash, verdict, detail)``.

    Returns:
        Dict mapping each hash to its ``(verdict, detail)`` pair. Verdicts include
        ``"not found"`` (VT has never seen it) and ``"error"`` (with the reason as
        detail) alongside the values from :func:`verdict_from_stats`.

    Raises:
        ImportError: if ``vt-py`` is not installed.
        ValueError: if ``api_key`` is empty.
    """
    import vt  # lazy: optional dependency

    if not api_key:
        raise ValueError("VirusTotal API key is required.")

    hashes = list(dict.fromkeys(h.lower() for h in hashes))  # dedupe, keep order
    total = len(hashes)
    out = {}
    # ponytail: no client-side throttling. Free VT keys allow ~4 lookups/min;
    # over that the API returns QuotaExceededError, surfaced per-hash below.
    # Add a rate limiter here if large batches become common.
    with vt.Client(api_key) as client:
        for index, digest in enumerate(hashes, start=1):
            if len(digest) == 128:  # SHA512 — VT only indexes MD5/SHA1/SHA256
                out[digest] = ("n/a", "SHA512 not supported by VT")
                if result_callback is not None:
                    result_callback(digest, *out[digest])
                if progress_callback is not None and total:
                    progress_callback(int(index * 100 / total))
                continue
            try:
                obj = client.get_object("/files/%s" % digest)
                verdict, detail = verdict_from_stats(obj.last_analysis_stats)
            except vt.error.APIError as error:
                if error.code == "NotFoundError":
                    verdict, detail = "not found", "not in VirusTotal"
                else:
                    verdict, detail = "error", error.code
            except Exception as error:  # network failure, etc.
                verdict, detail = "error", str(error)
            out[digest] = (verdict, detail)
            if result_callback is not None:
                result_callback(digest, verdict, detail)
            if progress_callback is not None and total:
                progress_callback(int(index * 100 / total))
    return out


def _demo():
    """Self-check for the pure verdict reducer (no network)."""
    assert verdict_from_stats({"malicious": 5, "harmless": 60, "undetected": 7}) == ("malicious", "5/72")
    assert verdict_from_stats({"malicious": 0, "suspicious": 2, "harmless": 70}) == ("suspicious", "2/72")
    assert verdict_from_stats({"malicious": 0, "harmless": 70, "undetected": 2}) == ("clean", "0/72")
    print("ok")


if __name__ == "__main__":
    _demo()
