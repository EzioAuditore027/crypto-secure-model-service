"""
Owner / Admin Application CLI Tool
Allows Owner/Admin to:
1. Approve pending users
2. Revoke user access
3. View and download collected feedback D'
4. Rebuild and deploy model M' = RebuildModel(D, D')
"""
import sys
import os
import json
import urllib.request
import urllib.parse

SERVER_URL = "http://127.0.0.1:8000"


def api_get(endpoint: str) -> dict:
    url = f"{SERVER_URL}{endpoint}"
    req = urllib.request.Request(url, headers={"User-Agent": "OwnerAdminCLI/1.0"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def api_post(endpoint: str, payload: dict) -> dict:
    url = f"{SERVER_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", "User-Agent": "OwnerAdminCLI/1.0"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    print("=" * 60)
    print("[*] OWNER / ADMIN MANAGEMENT CLI")
    print("=" * 60)

    try:
        info = api_get("/api/model/info")
        print(f"[*] Connected to Server. Active Model Version: v{info.get('active_version')}")
    except Exception as e:
        print(f"[!] Could not connect to Server at {SERVER_URL}. Is it running?")
        print(f"    Error: {e}")
        return

    while True:
        print("\nChoose an Owner operation:")
        print("1. List & Approve Pending Users (ApproveUser)")
        print("2. List All Users & Revoke Access (RemoveUser)")
        print("3. View Collected Feedback Dataset D' (ViewNewData)")
        print("4. Rebuild & Deploy Updated Model M' (RebuildModel)")
        print("5. Exit")
        choice = input("\nEnter choice [1-5]: ").strip()

        if choice == "1":
            res = api_get("/api/admin/pending_users")
            users = res.get("users", [])
            if not users:
                print("[*] No pending registration requests.")
                continue
            print(f"\nFound {len(users)} pending user(s):")
            for idx, u in enumerate(users, 1):
                print(f"  [{idx}] UID: {u['uid']} | Username: {u['username']}")
            approve_choice = input("\nEnter UID to approve (or 'all' / Enter to cancel): ").strip()
            if approve_choice.lower() == "all":
                for u in users:
                    api_post("/api/admin/approve_user", {"uid": u["uid"]})
                    print(f"[+] Approved {u['username']} ({u['uid']})")
            elif approve_choice:
                r = api_post("/api/admin/approve_user", {"uid": approve_choice})
                print("[+] Approval response:", r)

        elif choice == "2":
            res = api_get("/api/admin/all_users")
            users = res.get("users", [])
            print(f"\nTotal registered users: {len(users)}")
            for u in users:
                print(f"  UID: {u['uid']:<16} | User: {u['username']:<15} | Status: {u['status']}")
            revoke_uid = input("\nEnter UID to revoke (or Enter to cancel): ").strip()
            if revoke_uid:
                r = api_post("/api/admin/revoke_user", {"uid": revoke_uid})
                print("[+] Revocation response:", r)

        elif choice == "3":
            res = api_get("/api/admin/view_data")
            data = res.get("data", [])
            print(f"\nCollected Feedback Records in D' ({len(data)} items):")
            for item in data:
                lbl = "Phishing" if item["feedback_label"] == 1 else "Clean"
                print(f"  #{item['id']} [User {item['uid']}] Output: {item['prediction']} | Corrected: {lbl}")
                print(f"     Text: {item['query_text'][:80]}...")

        elif choice == "4":
            print("[*] Triggering RebuildModel(D, D') -> M' on server...")
            r = api_post("/api/admin/rebuild_model", {})
            print(f"[+] Result: {r.get('message')}")
            print(f"[+] New Active Version: v{r.get('version')}")

        elif choice == "5":
            print("Exiting Admin CLI.")
            break


if __name__ == "__main__":
    main()
