import requests

VULNERS_API_KEY = "KU3LPTW3SCDTO42VCJAW0PA0085M8HCFOJ31BRYYL2Y471P54CCEKW0COOAKMVZ6"

def fetch_cve_details(cve_id):
    url = "https://vulners.com/api/v3/search/id/"

    payload = {
        "id": cve_id,
        "references": True
    }

    try:
        response = requests.post(
            url,
            json=payload,
            params={"apiKey": VULNERS_API_KEY},
            timeout=10
        )

        response.raise_for_status()
        data = response.json()

        # Properly navigate Vulners response structure
        documents = data.get("data", {}).get("documents", {})

        if not documents:
            return {}

        doc = list(documents.values())[0]

        # ---- CVSS extraction logic (robust) ----
        cvss_score = 0
        severity = "Unknown"

        # Try CVSS v3 first
        if "cvss3" in doc:
            cvss_score = doc["cvss3"].get("baseScore", 0)

        # Fallback to CVSS v2
        elif "cvss" in doc:
            cvss_score = doc["cvss"].get("score", 0)

        # Calculate severity manually if missing
        if cvss_score >= 9:
            severity = "Critical"
        elif cvss_score >= 7:
            severity = "High"
        elif cvss_score >= 4:
            severity = "Medium"
        elif cvss_score > 0:
            severity = "Low"

        return {
            "cvss": float(cvss_score),
            "severity": severity,
            "title": doc.get("title", ""),
            "exploit_available": bool(doc.get("exploit", False))
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}

    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}