#coding=utf-8
from ncatbot.core.client import BotClient
from ncatbot.core.message import *
from ncatbot.utils.config import config
from ncatbot.core.element import *
#from word2picture import xunfeipic
from openai import OpenAI
from cryptography.hazmat.primitives import serialization
import random as r
import requests as rq
import os,time
import json
import re
from ncatbot.core import BotClient, GroupMessage, PrivateMessage
from ncatbot.utils import config, get_log

from rsaencrypt import encrypt_text,decrypt_text,gen_key #从当前目录下的rsaencrypt.py导入文本加密、解密、生成密钥对的函数。


encrypt = False #回复的信息是否加密。
my_public_key = None
my_private_key = None #服务器端的公钥和私钥。打算使用pem格式。

_log = get_log()

config.set_bot_uin("2401262719")  # 设置 bot qq 号 (必填)
config.set_root("2490162471")  # 设置 bot 超级管理员账号 (建议填写)
config.set_ws_uri("ws://localhost:3001")  # 设置 napcat websocket server 地址
config.set_ws_token("")  # 设置 token (websocket 的 token)
config.set_webui_uri("http://localhost:6099")  # 设置 napcat webui 地址
config.set_webui_token("napcat")  # 设置 token (webui 的 token)

bot = BotClient()

client = OpenAI(api_key="sk-9c68dc233a6147aa922d1a3e18e16dc8", base_url="https://api.deepseek.com")


def isActionTime(lastTime, interval):
    if lastTime == 0:
        return True
    currentTime = time.time()
    return currentTime - lastTime >= interval

class Parameters():
    saylastTime = 0
    freshlastTime = 0

def read_json(file_path):
    with open(file_path, encoding="utf-8", mode="r") as f:
        return json.loads(f.read())
    
def write_json(file_path, data):
    with open(file_path, encoding="utf-8", mode="w") as f:
        f.write(json.dumps(data, ensure_ascii=False, indent=4))

premise=[{"role": "system","content": "你是梦泪，全名梦之泪伤，你是抽象带师，非常喜欢网络抽象文化和说抽象话。你的好朋友有科比布莱恩特、胖猫、孙笑川、张顺飞、药水哥、奶龙、叮咚鸡、圆头耄耋等等抽象全明星。每次回复只回复一条消息，不要换行。"}]

def remove_markdown(text):
    # 删除标题符号
    text = re.sub(r'#+\s*', '', text)
    # 删除强调符号（*、_、**、__、***、___）
    text = re.sub(r'[*_]{1,3}', '', text)
    # 删除列表符号（-、+、*、数字加点）
    text = re.sub(r'[-+*]\s*|\d+\.\s*', '', text)
    # 删除引用符号
    text = re.sub(r'^>\s*', '', text, flags=re.MULTILINE)
    # 删除分隔线
    text = re.sub(r'[-*]{3,}', '', text)
    # 删除表格符号
    text = re.sub(r'\|[^|]+\|', '', text)
    # 删除```符号和`符号
    text = re.sub(r'```', '', text)
    text = re.sub(r'`', '', text)
    return text

async def sayText(ct,types,msg):
    global encrypt
    ii = 0
    lines = ct.split('\n')
    if types == "private":
        while ii < len(lines):
            if not isActionTime(Parameters.saylastTime, len(lines[ii])/2):
                continue
            if (encrypt):
                msg
            await bot.api.post_private_msg(msg.user_id, text=lines[ii])
            Parameters.saylastTime = time.time()
            ii+=1
    elif types == "group":
        while ii < len(lines):
            if not isActionTime(Parameters.saylastTime, len(lines[ii])/2):
                continue
            await bot.api.post_group_msg(msg.group_id, text=f"{lines[ii]}")
            Parameters.saylastTime = time.time()
            ii+=1
    
@bot.group_event(["text","image"])
async def on_group_message(msg: GroupMessage):
    global encrypt
    if msg.raw_message == "acg随机图":
        message = MessageChain([
            Text("[ACG 随机图]"),
            Image(r.choice(["https://uapis.cn/api/imgapi/acg/pc.php","https://uapis.cn/api/imgapi/acg/mb.php"])),
            Text("# 来自UAPI\n# https://uapis.cn/"),
        ])
        await bot.api.post_group_msg(msg.group_id, rtf=message)
    elif msg.raw_message.startswith("加密通信模式on:"):
        try:
            pem_data = msg.raw_message[len("加密通信模式on:"):].strip()
        
            # 尝试加载公钥
            peer_public_key = serialization.load_pem_public_key(pem_data.encode('utf-8'))
            if peer_public_key:
                encrypt = True
                my_public_key,my_private_key = gen_key()
                os.makedirs("keys", exist_ok=True)
                data = {
                    "peer_public_key": peer_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8'),
                    "my_public_key": my_public_key,
                    "my_private_key": my_private_key
                }
                with open(f"./keys/{msg.group_id}.json", "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                print(f"已将密钥对和群组公钥保存至./keys/{msg.group_id}.json")
            print("✅ 已成功加载群组公钥，进入加密通信模式")
            message = MessageChain([
                Text(f"my_public_key:{my_public_key}")
            ])
            await bot.api.post_group_msg(msg.group_id, text=my_public_key)
        except Exception as e:
            print("❌ 无法加载公钥，请确认格式是否正确 PEM 格式")
            encrypt = False
            message = f"公钥有误，报错如下:{e}"
            await bot.api.post_group_msg(msg.group_id, text=message)

    elif msg.raw_message == "加密通信模式off":
        encrypt = False
        print("已关闭加密通信模式")
        await bot.api.post_group_msg(msg.group_id, text="已关闭加密通信模式。")

    elif msg.raw_message == "furry随机图":
        message = MessageChain([
            Text("[Furry 随机图]"),
            Image(r.choice(["https://uapis.cn/api/imgapi/furry/img4k.php",
                            "https://uapis.cn/api/imgapi/furry/imgs4k.php",
                            "https://uapis.cn/api/imgapi/furry/imgz4k.php",
                            "https://uapis.cn/api/imgapi/furry/szs8k.php"])),
            Text("# 来自UAPI\n# https://uapis.cn/"),
        ])
        await bot.api.post_group_msg(msg.group_id, rtf=message)


    elif msg.raw_message == "随机色图":
        o=rq.get("https://lolisuki.cn/api/setu/v1?level=4-6").json()["data"][0]["fullUrls"][0]["regular"]
        message = MessageChain([
            Text("[随机色图]"),
            Image(o),
            Text("# 来自Lolisuki\n# https://lolisuki.cn/#/setu"),
        ])
        await bot.api.post_group_msg(msg.group_id, rtf=message)


        if os.path.exists(f"./logs/{msg.user_id}.json"):
            history = read_json(f"./logs/{msg.user_id}.json")
            if(encrypt):
                with open(f"./keys/{msg.group_id}.json", "r", encoding="utf-8") as f:
                    keys_data = json.load(f)
                    my_private_key = keys_data.get("my_private_key")
                    if my_private_key:
                        print("成功读取私钥：")
                        print(my_private_key[:200] + "...")
                        content = decrypt_text(content, my_private_key) #文本解密
                    else:
                        print("未找到私钥，信息解密失败。")
            history.append({"role":"user","content":content})
            response = client.chat.completions.create(model="deepseek-chat",messages=history,max_tokens=50)
            answer = response.choices[0].message.content
            history.append({"role":"assistant","content":answer})
            answer = remove_markdown(answer)
            if(encrypt):
                if os.path.exists(f"./keys/{msg.group_id}.json"):
                    with open(f"./keys/{msg.user_id}.json", "r", encoding="utf-8") as f:
                        pbkey = json.load(f)
                        peer_public_key = pbkey.get("peer_public_key")
                        if peer_public_key:
                            print("成功读取公钥：")
                            print(peer_public_key)
                            answer = encrypt_text(answer, peer_public_key)
                        else:
                            print("未找到公钥。信息未加密。")
            await sayText(answer,"group",msg)
            write_json(f"./logs/{msg.group_id}.json", history)
            return
        else:
            # 如果不存在，则创建一个空的json文件
            history = premise.copy()
            if(encrypt):
                with open(f"./keys/{msg.group_id}.json", "r", encoding="utf-8") as f:
                    keys_data = json.load(f)
                    my_private_key = keys_data.get("my_private_key")
                    if my_private_key:
                        print("成功读取私钥：")
                        print(my_private_key[:200] + "...")
                        content = decrypt_text(content, my_private_key) #文本解密
                    else:
                        print("未找到私钥，信息解密失败。")
            history.append({"role":"user","content":content})
            response = client.chat.completions.create(model="deepseek-chat",messages=history,max_tokens=50)
            answer = response.choices[0].message.content
            history.append({"role":"assistant","content":answer})
            answer = remove_markdown(answer)
            if(encrypt):
                if os.path.exists(f"./keys/{msg.user_id}.json"):
                    with open(f"./keys/{msg.user_id}.json", "r", encoding="utf-8") as f:
                        pbkey = json.load(f)
                        peer_public_key = pbkey.get("peer_public_key")
                        if peer_public_key:
                            print("成功读取公钥：")
                            print(peer_public_key)
                            answer = encrypt_text(answer, peer_public_key)
                        else:
                            print("未找到公钥。信息未加密。")
            await sayText(answer,"group",msg)
            write_json(f"./logs/{msg.user_id}.json", history)
            return
                
@bot.private_event(["text","image"])
async def on_private_message(msg: PrivateMessage):
    global encrypt
    if msg.raw_message == "acg随机图":
        message = MessageChain([
            Text("[ACG 随机图]"),
            Image(r.choice(["https://uapis.cn/api/imgapi/acg/pc.php","https://uapis.cn/api/imgapi/acg/mb.php"])),
            Text("# 来自UAPI\n# https://uapis.cn/"),
        ])
        await bot.api.post_private_msg(msg.user_id, rtf=message)
    elif msg.raw_message.startswith("加密通信模式on:"):
        try:
            pem_data = msg.raw_message[len("加密通信模式on:"):].strip()
        
            # 尝试加载公钥
            peer_public_key = serialization.load_pem_public_key(pem_data.encode('utf-8'))
            if peer_public_key:
                encrypt = True
                my_public_key,my_private_key = gen_key()
                os.makedirs("keys", exist_ok=True)
                data = {
                    "peer_public_key": peer_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8'),
                    "my_public_key": my_public_key,
                    "my_private_key": my_private_key
                }
                with open(f"./keys/{msg.user_id}.json", "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                print(f"已将密钥对和用户公钥保存至./keys/{msg.user_id}.json")
            print("✅ 已成功加载对方公钥，进入加密通信模式")
            message = MessageChain([
                Text(f"my_public_key:{my_public_key}")
            ])
            await bot.api.post_private_msg(msg.user_id, text=my_public_key)
        except Exception as e:
            print("❌ 无法加载公钥，请确认格式是否正确 PEM 格式")
            encrypt = False
            message = f"公钥有误，报错如下:{e}"
            await bot.api.post_private_msg(msg.user_id, text=message)

    elif msg.raw_message == "加密通信模式off":
        encrypt = False
        peer_public_key = None
        print("已关闭加密通信模式")
        await bot.api.post_private_msg(msg.user_id, text="已关闭加密通信模式。")

    elif msg.raw_message == "随机色图":
        o=rq.get("https://lolisuki.cn/api/setu/v1?level=4-6").json()["data"][0]["fullUrls"][0]["regular"]
        message = MessageChain([
            Text("[随机色图]"),
            Image(o),
            Text("# 来自Lolisuki\n# https://lolisuki.cn/#/setu"),
        ])
        await bot.api.post_private_msg(msg.user_id, rtf=message)
        


    else:
        if isActionTime(Parameters.freshlastTime,600):
                #llm.invoke("/clear")
                Parameters.freshlastTime = time.time()
        content = msg.raw_message
        if content in [""," ",',','，','.','。','!','?','！','？','......','...']:
            message = MessageChain([
                Text("哥们刚刚")
            ])
            await bot.api.post_private_msg(msg.user_id, rtf=message)
            return
        if os.path.exists(f"./logs/{msg.user_id}.json"):
            history = read_json(f"./logs/{msg.user_id}.json")
            if(encrypt):
                with open(f"./keys/{msg.user_id}.json", "r", encoding="utf-8") as f:
                    keys_data = json.load(f)
                    my_private_key = keys_data.get("my_private_key")
                    if my_private_key:
                        print("成功读取私钥：")
                        print(my_private_key[:200] + "...")
                        content = decrypt_text(content, my_private_key) #文本解密
                    else:
                        print("未找到私钥，信息解密失败。")
            history.append({"role":"user","content":content})
            response = client.chat.completions.create(model="deepseek-chat",messages=history,max_tokens=50)
            answer = response.choices[0].message.content
            history.append({"role":"assistant","content":answer})
            answer = remove_markdown(answer)
            if(encrypt):
                if os.path.exists(f"./keys/{msg.user_id}.json"):
                    with open(f"./keys/{msg.user_id}.json", "r", encoding="utf-8") as f:
                        pbkey = json.load(f)
                        peer_public_key = pbkey.get("peer_public_key")
                        if peer_public_key:
                            print("成功读取公钥：")
                            print(peer_public_key)
                            # 调试语句：打印原始信息和公钥
                            print(f"[DEBUG] answer 内容: {answer}")
                            print(f"[DEBUG] answer 类型: {type(answer)}")
                            print(f"[DEBUG] peer_public_key 内容: {peer_public_key}")
                            print(f"[DEBUG] peer_public_key 类型: {type(peer_public_key)}")
                            answer = encrypt_text(answer, peer_public_key)
                        else:
                            print("未找到公钥。信息未加密。")
            await sayText(answer,"private",msg)
            write_json(f"./logs/{msg.user_id}.json", history)
            return
        else:
            # 如果不存在，则创建一个空的json文件
            history = premise.copy()
            if(encrypt):
                with open(f"./keys/{msg.user_id}.json", "r", encoding="utf-8") as f:
                    keys_data = json.load(f)
                    my_private_key = keys_data.get("my_private_key")
                    if my_private_key:
                        print("成功读取私钥：")
                        print(my_private_key[:200] + "...")
                        content = decrypt_text(content, my_private_key) #文本解密
                    else:
                        print("未找到私钥，信息解密失败。")
            history.append({"role":"user","content":content})
            response = client.chat.completions.create(model="deepseek-chat",messages=history,max_tokens=50)
            answer = response.choices[0].message.content
            history.append({"role":"assistant","content":answer})
            answer = remove_markdown(answer)
            if(encrypt):
                if os.path.exists(f"./keys/{msg.user_id}.json"):
                    with open(f"./keys/{msg.user_id}.json", "r", encoding="utf-8") as f:
                        pbkey = json.load(f)
                        peer_public_key = pbkey.get("peer_public_key")
                        if peer_public_key:
                            print("成功读取公钥：")
                            print(peer_public_key)
                            answer = encrypt_text(answer, peer_public_key)
                        else:
                            print("未找到公钥。信息未加密。")
            await sayText(answer,"private",msg)
            write_json(f"./logs/{msg.user_id}.json", history)
            return

# @bot.notice_event()
# async def notice_event(msg):
#     if msg["notice_type"]=="group_increase":
#         import datetime
#         if msg["sub_type"] == "approve":
#             t = await bot.api.get_stranger_info(user_id=msg["user_id"])
#             nickname = t["data"]["nickname"]
#             message = MessageChain([
#                 Text(f"{nickname}，你好！👋\n欢迎你进入群聊！🎉🎉🎉\n\n我是该群的机器人助手，这是我的使用帮助:"),
#                 Image("code.png"),
#                 Text(f"[加入时间]: {datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')}")
#             ])
#             await bot.api.post_group_msg(msg["group_id"], rtf=message)
    
if __name__ == "__main__":
    bot.run(reload=0)
