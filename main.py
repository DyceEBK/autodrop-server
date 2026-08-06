from fastapi import FastAPI, Request, HTTPException
import hmac
import hashlib
import base64
import os

app = FastAPI()

# This reads the secret key from Render environment variables
SHOPIFY_SECRET = os.getenv("SHOPIFY_CLIENT_SECRET", "")

def verify_webhook(data: bytes, hmac_header: str):
    """Verifies the webhook actually came from your Shopify store."""
    if not SHOPIFY_SECRET:
        return True # Bypass in testing if secret isn't set yet
    digest = hmac.new(SHOPIFY_SECRET.encode('utf-8'), data, hashlib.sha256).digest()
    computed_hmac = base64.b64encode(digest).decode('utf-8')
    return hmac.compare_digest(computed_hmac, hmac_header)

@app.get("/")
def home():
    return {"status": "AutoDrop Brain is running successfully!"}

@app.post("/webhook/order-paid")
async def catch_order(request: Request):
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    
    # Check security header
    if hmac_header and not verify_webhook(body, hmac_header):
        raise HTTPException(status_code=401, detail="Unauthorized")

    order_data = await request.json()
    order_id = order_data.get("id")
    customer_name = order_data.get("shipping_address", {}).get("first_name", "Customer")
    
    # Print to server log when an order comes in
    print(f"🎉 BINGO! Received paid order #{order_id} for {customer_name}!")
    
    return {"status": "success"}
