# -*- coding: utf-8 -*-
import os
from openai import OpenAI
import sys


def analyze_honeypot():
    # Get token address from command line argument
    if len(sys.argv) != 2:
        print("Usage: python honeypot_detector.py <token_address>")
        sys.exit(1)

    token_address = sys.argv[1].lower()
    tmp_file = f"tmp_{token_address}.txt"

    # Read source code from tmp_{token_address}.txt
    with open(tmp_file, "r", encoding='utf-8') as f:
        code = f.read()

    messages = [
        {
            "role": "system",
            "content": "你是一个erc20 honeypot分析师,擅长分析erc20合约的代码,并判断是否为honeypot。判断的依据如下: \
                1. transferFrom调用了恶意函数,或者调用的approve函数被改成了恶意函数,使得owner、taxwallet、dev,_deadAddr等特权地址可以调整其他交易者的allowance,如果可以设置,则是。 \
                2. 除了transferFrom和approve这种合理修改allowance的函数之外,还有没有其他的伪装函数可以修改allowance,如果有,则是。 \
                3. 是否可以修改其他用户的balance(从合约里提取代币到dev不算),如果可以修改,则是。 \
                4. 在transferFrom函数中,是否存在特权地址(如owner、taxwallet、dev、_deadAddr等)可以绕过allowance的检查,如果有,则是。 \
                5. renounceOwnership函数是否被篡改的和renounce无关(如果除了正常renounce之外还有转出余额的操作没有关系,不是honeypot),如果被篡改,则是。 \
                6. 调税机制是否允许往大于50的方向调整,如果可以调整,则是。 \
                7. 在卖出的时候,是否有调用了某些函数用来累计当前token的买入量并在超过一定数量后就不允许散户卖出(忽略每个块只有3次即以上卖出的情况,只考虑针对当前累积买入量来做限制),如果有,则是。"
        },
        {
            "role": "user",
            "content": f"请根据判断依据分析以下合约代码,判断是否为honeypot,结果只需要说是+上述依据的标号或者否，不用说别的！:{code}"
        },
    ]

    client = OpenAI(
        base_url="https://api.x.ai/v1",
        api_key="",
    )

    print("client created")

    completion = client.chat.completions.create(
        model="grok-3-mini-beta",
        messages=messages,
        temperature=0,
    )

    print("completion created")

    print("Reasoning Content:")
    print(completion.choices[0].message.reasoning_content)

    print("\nFinal Response:")
    print(completion.choices[0].message.content)

    print("\nNumber of completion tokens (input):")
    print(completion.usage.completion_tokens)

    print("\nNumber of reasoning tokens (input):")
    print(completion.usage.completion_tokens_details.reasoning_tokens)


if __name__ == "__main__":
    analyze_honeypot()
