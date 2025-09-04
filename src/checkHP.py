#!/usr/bin/env python3
import aiohttp
import asyncio
import sys
from typing import Optional, Tuple, List
from configs import *


async def check_honeypot(token_address: str, source_code, model: str = "grok", log_hook=None) -> Optional[Tuple[bool, List[int]]]:
    """
    异步检查代币是否为蜜罐
    :param token_address: ERC20代币地址
    :param source_code: 合约源代码
    :param model: AI模型名称 ("grok" 或 "claude")
    :param log_hook: 日志钩子
    :return: Tuple of (is_honeypot, reasons) if successful, None if error
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                HP_END_POINTS,
                json={
                    "token_address": token_address,
                    "source_code": source_code,
                    "model": model
                }
            ) as response:

                if response.status == 200:
                    result = await response.json()
                    return result["is_honeypot"], result.get("reasons", [])
                else:
                    detail = await response.json()
                    info = f"Error: {detail.get('detail', 'Unknown error')}"
                    if log_hook:
                        log_hook.服务器报错 = info
                    print(info)
                    return None

    except aiohttp.ClientError as e:
        info = f"Error connecting to server: {e}"
        if log_hook:
            log_hook.服务器报错2 = info
        print(info)
        return None


async def check_ca(token_address: str, model: str = "grok"):
    """
    异步检查代币地址并打印是否为蜜罐
    :param token_address: ERC20代币地址
    :param model: AI模型名称 ("grok" 或 "claude")
    """
    # 简单的地址格式验证
    if not token_address.startswith("0x") or len(token_address) != 42:
        print("Error: Invalid token address format")
        print("Token address should start with '0x' and be 42 characters long")
        return

    print(f"Checking token: {token_address}")
    print(f"Using AI model: {model}")

    result = await check_honeypot(token_address, None, model)

    if result is None:
        return
    
    is_honeypot, reasons = result
    
    if is_honeypot:
        print("⚠️ Warning: This token is a honeypot!")
        if reasons:
            print("\nDetection reasons:")
            reason_descriptions = {
                1: "transferFrom调用了恶意函数,或者调用的approve函数被改成了恶意函数",
                2: "可以修改其他用户的balance",
                3: "特权地址可以绕过allowance的检查",
                4: "renounceOwnership函数被篡改",
                5: "调税机制允许往大于50的方向调整",
                6: "在卖出时根据累积买入量限制散户卖出"
            }
            for reason in reasons:
                if reason in reason_descriptions:
                    print(f"- {reason_descriptions[reason]}")
    else:
        print("✅ This token is not a honeypot")


def main(token_address: str, model: str = "grok"):
    asyncio.run(check_ca(token_address, model))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <token_address> [model]")
        print("model: grok (default) or claude")
        sys.exit(1)
    
    token_address = sys.argv[1]
    model = sys.argv[2] if len(sys.argv) > 2 else "grok"
    
    if model not in ["grok", "claude"]:
        print("Error: model must be either 'grok' or 'claude'")
        sys.exit(1)
        
    main(token_address, model)
