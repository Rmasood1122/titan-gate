***# Titan Gate — Examples***



***## sample-repo***



***A minimal working example showing how to integrate Titan Gate into any GitHub repo.***



***\*\*What it shows:\*\****

***- `.github/workflows/titan-gate.yml` — one-file integration***

***- `.titan/receipts/` — where receipts are stored***

***- 3-step setup guide***



***\*\*Copy this to your repo:\*\****

***1. Copy `.github/workflows/titan-gate.yml` into your repo***

***2. Add `TITAN\_SIGNING\_KEY` secret to your repo settings***

***3. Open a PR — receipts generate automatically***



***## Verify a receipt***

***```bash***

***python scripts/titan\_verify.py <receipt.json> --key <your-key>***

***```***



***## More***



***- \[Full spec](../docs/SPEC.md)***

***- \[Architecture](../docs/TITAN\_GATE\_ARCHITECTURE.md)***

***- \[GitHub Action](../action.yml)***

