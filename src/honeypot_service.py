# -*- coding: utf-8 -*-
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
import json
import subprocess
import tempfile
import os
import requests
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from database import get_db, HoneypotRecord, init_db
from contextlib import asynccontextmanager
import re
import logging
from datetime import datetime
import pathlib

# Load environment variables
load_dotenv()

# Create logs directory if it doesn't exist
LOGS_DIR = pathlib.Path("logs")
LOGS_DIR.mkdir(exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    yield
    # Shutdown
    pass

app = FastAPI(lifespan=lifespan)

# Etherscan API configuration
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
if not ETHERSCAN_API_KEY:
    raise ValueError("ETHERSCAN_API_KEY environment variable is not set")


class TokenRequest(BaseModel):
    token_address: str
    source_code: Optional[str] = None  # 新增字段，默认为 None


def setup_logger(token_address: str) -> logging.Logger:
    """Setup logger for a specific token"""
    logger = logging.getLogger(f"honeypot_{token_address}")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    # Create log file handler
    log_file = LOGS_DIR / f"{token_address.lower()}.log"
    file_handler = logging.FileHandler(
        log_file, encoding='utf-8')  # ✅ 加上 encoding

    file_handler.setLevel(logging.INFO)

    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(file_handler)

    return logger


def get_contract_source_code(address: str) -> str:
    """Fetch contract source code from Etherscan"""
    url = f"https://api.etherscan.io/v2/api?chainid=1"
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": ETHERSCAN_API_KEY
    }

    response = requests.get(url, params=params)
    if response.status_code != 200:
        raise HTTPException(
            status_code=500, detail="Failed to fetch from Etherscan")

    data = response.json()
    if data["status"] != "1" or data["message"] != "OK":
        raise HTTPException(
            status_code=500, detail=f"Etherscan API error: {data.get('message', 'Unknown error')}")

    if not data["result"] or not data["result"][0]["SourceCode"]:
        raise HTTPException(
            status_code=404, detail="Contract source code not found")

    return data["result"][0]["SourceCode"]


def extract_reasons(output: str) -> List[int]:
    """Extract detection reasons from the honeypot detector output"""
    # Find the "Final Response:" line and get the next line
    lines = output.split('\n')
    final_response = None
    for i, line in enumerate(lines):
        if line.startswith('Final Response:'):
            if i + 1 < len(lines):
                final_response = lines[i + 1].strip()
            break

    if not final_response:
        return [0]

    # If the response contains "否" or "no", return [0]
    if "否" in final_response.lower() or "no" in final_response.lower():
        return [0]

    # If the response contains "是+", extract the numbers after it
    if "是" in final_response:
        numbers = re.findall(r'\d+', final_response)
        if numbers:
            return [int(num) for num in numbers]

    return [0]


def analyze_contract(source_code: str, logger: logging.Logger, token_address: str) -> tuple[bool, List[int]]:
    """Analyze contract using honeypot detector"""
    # Write source code to tmp_{token_address}.txt
    tmp_file = f"tmp_{token_address.lower()}.txt"
    with open(tmp_file, "w", encoding='utf-8') as f:
        f.write(source_code)

    try:
        # Run the honeypot detector script
        result = subprocess.run(
            ['python', 'honeypot_detector.py', token_address],
            capture_output=True,
            text=True,
            env={**os.environ, 'PYTHONPATH': os.getcwd()}
        )

        if result.returncode != 0:
            logger.error(f"Script execution failed: {result.stderr}")
            raise Exception(f"Script execution failed: {result.stderr}")

        # Log the raw output
        logger.info("Grok Analysis Output:")
        logger.info(result.stdout)
        
        # Parse the output to determine if it's a honeypot and get reasons
        output = result.stdout.strip()
        reasons = extract_reasons(output)
        is_honeypot = len(reasons) > 0 and reasons[0] != 0

        # Log the analysis result
        logger.info(f"Analysis Result - Is Honeypot: {is_honeypot}")
        logger.info(f"Detection Reasons: {reasons}")

        return is_honeypot, reasons

    finally:
        # Clean up the tmp file
        if os.path.exists(tmp_file):
            os.remove(tmp_file)

@app.post("/check-honeypot")
async def check_honeypot(request: TokenRequest, db: Session = Depends(get_db)):
    try:
        # Setup logger for this token
        logger = setup_logger(request.token_address)
        logger.info(
            f"Starting honeypot check for token: {request.token_address}")

        # Check if record exists in database
        record = db.query(HoneypotRecord).filter(
            HoneypotRecord.token_address == request.token_address.lower()
        ).first()

        if record:
            logger.info(
                f"Found cached result - Is Honeypot: {record.is_honeypot}")
            return {
                "token_address": record.token_address,
                "is_honeypot": record.is_honeypot,
                "reasons": record.reasons,
                "cached": True
            }

        # If not in database, get source code and analyze
        logger.info("Fetching contract source code from Etherscan")
        if request.source_code is not None:
            source_code = request.source_code
            logger.info("Using source code provided in request.")
        else:
            logger.info("Fetching contract source code from Etherscan")
            source_code = get_contract_source_code(request.token_address)

        is_honeypot, reasons = analyze_contract(
            source_code, logger, request.token_address)

        # Create new record
        new_record = HoneypotRecord(
            token_address=request.token_address.lower(),
            is_honeypot=is_honeypot,
            reasons=reasons
        )

        # Save to database
        logger.info("Saving results to database")
        db.add(new_record)
        db.commit()
        db.refresh(new_record)

        return {
            "token_address": new_record.token_address,
            "is_honeypot": new_record.is_honeypot,
            "reasons": new_record.reasons,
            "cached": False
        }

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
