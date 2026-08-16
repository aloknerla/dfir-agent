

def test_the_bundle_names_a_call_the_run_could_not_complete(monkeypatch) -> None:
    """Zapreka na koju je izvođenje naišlo mora doći pred provjeru.

    Izmjereno: izlučivanje je javilo da je arhiva šifrirana i da lozinka nije
    predana, a objavljeni je odgovor tvrdio da zapisa o pogrešci ni o šifriranju
    nema. Provjera to nije mogla opovrgnuti, jer neuspio poziv nije dokaz pa u
    snop nikad nije ni ušao.
    """

    from forensic_agent.agent.verifier_projection import _verifier_evidence_bundle

    bundle = _verifier_evidence_bundle(
        [],
        source_result_count=0,
        total_truncated=False,
        obstacles=[
            {
                "tool": "archive_query",
                "status": "error",
                "code": "legacy_error",
                "message": "the archive is encrypted and no password was supplied",
            }
        ],
    )

    assert bundle["obstacles"][0]["tool"] == "archive_query"
    assert "encrypted" in bundle["obstacles"][0]["message"]
    # Zapreke stoje izvan rezultata, jer ne smiju potkrijepiti nijednu tvrdnju.
    assert bundle["results"] == []
