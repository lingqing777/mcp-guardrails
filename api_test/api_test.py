from openai import OpenAI

client = OpenAI(
    # 实际api_key从.env中读取
    api_key="sk-xxx" , #已隐藏，实际api_key替换
    base_url="https://[YOUR WORKPLACE ID].cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
)

messages = [{"role": "user", "content": "你是什么模型，不要任何冗余输出"}]
completion = client.chat.completions.create(
    model="qwen-turbo",  # 您可以按需更换为其它深度思考模型
    messages=messages,
    extra_body={"enable_thinking": False},
    stream=True
)
is_answering = False  # 是否进入回复阶段

for chunk in completion:
    if not chunk.choices:
        continue
    delta = chunk.choices[0].delta
    if hasattr(delta, "reasoning_content") and delta.reasoning_content is not None:
        if not is_answering:
            print(delta.reasoning_content, end="", flush=True)
    if hasattr(delta, "content") and delta.content:
        if not is_answering:
            is_answering = True
        print(delta.content, end="", flush=True)