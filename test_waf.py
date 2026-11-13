import requests

def test_waf():
    # 1. Benign request
    benign_url = "http://localhost:8080/search?q=shoes"
    res_benign = requests.get(benign_url)
    print(f"Benign Request:    GET {benign_url}")
    print(f"Status Code:       {res_benign.status_code} ({'Allowed' if res_benign.status_code == 200 else 'Failed'})")
    print(f"Response:          {res_benign.text}\n")

    # 2. Malicious SQLi request
    sqli_url = "http://localhost:8080/search?q=' OR '1'='1"
    res_sqli = requests.get(sqli_url)
    print(f"Malicious Request: GET {sqli_url}")
    print(f"Status Code:       {res_sqli.status_code} ({'Blocked by ModSecurity' if res_sqli.status_code == 403 else 'Not Blocked'})")
    print(f"Response (first 100 chars): {res_sqli.text[:100].strip()}...\n")

if __name__ == "__main__":
    test_waf()
