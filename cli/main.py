import requests

def start_scan():
    target = input("Enter target domain: ").strip()

    if not target:
        print("Target cannot be empty.")
        return

    print(f"\nStarting scan for {target}...\n")

    # start scan via POST with JSON body
    response = requests.post(
        "http://127.0.0.1:5000/scan",
        json={"target": target}
    )
    data = response.json()

    if "scan_id" not in data:
        print("Error starting scan:", data)
        return

    scan_id = data["scan_id"]
    print("Scan ID:", scan_id)

    print("\nWaiting for scan to complete...\n")

    # poll the correct endpoint (/scan/<scan_id>)
    while True:
        result = requests.get(f"http://127.0.0.1:5000/scan/{scan_id}").json()

        if result.get("status") == "completed":
            print("\nScan Completed!\n")
            print(result)
            break

if __name__ == "__main__":
    start_scan()