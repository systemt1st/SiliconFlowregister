#Github：https://github.com/systemt1st
import threading
import time
import uuid
import requests
import json
import logging
import random
import os
from twocaptcha import TwoCaptcha
from requests.exceptions import RequestException, Timeout, ConnectionError


# ================== 配置信息
class Config:
    # API配置
    API_KEY = 'xxx'  # 2Captcha api key
    PID = '825829'  # 接码平台项目id
    SHARE_CODE = 'KAlxO6hf'  # 硅基流动邀请码
    USERNAME = 'xxx'  # 接码平台账号
    PASSWORD = 'xxx'  # 接码平台密码

    # 运行参数
    MAX_RETRIES = 3  # 最大重试次数
    RETRY_DELAY = 3  # 重试延迟(秒)
    REQUEST_TIMEOUT = 30  # 请求超时时间(秒)
    SMS_WAIT_TIME = 60  # 等待短信最长时间(秒)
    SMS_CHECK_INTERVAL = 2  # 检查短信间隔(秒)
    THREAD_COUNT = 1  # 线程数量
    MAX_ACCOUNTS_PER_THREAD = 50  # 每个线程最大注册账号数
    RATE_LIMIT_DELAY = (5, 15)  # 操作间隔随机延迟范围(秒)

    # 输出设置
    OUTPUT_FILE = 'silicon.txt'
    LOG_FILE = 'registration.log'
    LOG_LEVEL = logging.INFO


# 设置日志系统
def setup_logging():
    if not os.path.exists('logs'):
        os.makedirs('logs')

    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f"logs/{Config.LOG_FILE}"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)


logger = setup_logging()


# ================== GeeTest V4 验证码解决
def solve_geetest_v4():
    solver = TwoCaptcha(Config.API_KEY)
    challenge = str(uuid.uuid4())  # 生成唯一的challenge
    logger.info(f"开始解决验证码，challenge: {challenge}")

    for attempt in range(Config.MAX_RETRIES):
        try:
            result = solver.geetest_v4(captcha_id='592ad182314270f0c1442d9aa82d3ac2',
                                       url='https://2captcha.com/demo/geetest-v4',
                                       challenge=challenge)
            logger.info("验证码解决成功")
            return result
        except Exception as e:
            logger.error(f"验证码解决失败 (尝试 {attempt + 1}/{Config.MAX_RETRIES}): {e}")
            if attempt < Config.MAX_RETRIES - 1:
                sleep_time = Config.RETRY_DELAY * (attempt + 1)
                time.sleep(sleep_time)

    logger.error("验证码解决失败，已达到最大重试次数")
    return None


# ================== 椰子接码平台
def yezi_login(username, password):
    for attempt in range(Config.MAX_RETRIES):
        try:
            logger.info("正在登录接码平台...")
            resp = requests.get(
                f'http://api.sqhyw.net:90/api/logins?username={username}&password={password}',
                timeout=Config.REQUEST_TIMEOUT
            )

            if resp.status_code != 200:
                logger.error(f"接码平台登录失败，状态码: {resp.status_code}")
                continue

            resp_data = resp.json()
            logger.debug(f"接码平台登录结果: {resp_data}")

            if 'token' not in resp_data or not resp_data['token']:
                logger.error(f"接码平台登录失败，未获取到token: {resp_data}")
                if attempt < Config.MAX_RETRIES - 1:
                    time.sleep(Config.RETRY_DELAY)
                continue

            logger.info("接码平台登录成功")
            return resp_data['token']

        except (RequestException, ConnectionError, Timeout) as e:
            logger.error(f"接码平台登录请求出错 (尝试 {attempt + 1}/{Config.MAX_RETRIES}): {e}")
            if attempt < Config.MAX_RETRIES - 1:
                time.sleep(Config.RETRY_DELAY)
        except (ValueError, KeyError) as e:
            logger.error(f"接码平台登录结果解析错误: {e}")
            if attempt < Config.MAX_RETRIES - 1:
                time.sleep(Config.RETRY_DELAY)

    logger.error("接码平台登录失败，已达到最大重试次数")
    return None


def yezi_mobile(token, pid):
    if not token:
        logger.error("获取手机号失败: token无效")
        return None

    for attempt in range(Config.MAX_RETRIES):
        try:
            logger.info("正在获取手机号...")
            resp = requests.get(
                f'http://api.sqhyw.net:90/api/get_mobile?token={token}&project_id={pid}',
                timeout=Config.REQUEST_TIMEOUT
            )

            if resp.status_code != 200:
                logger.error(f"获取手机号失败，状态码: {resp.status_code}")
                continue

            resp_data = resp.json()
            logger.debug(f"获取手机号结果: {resp_data}")

            if 'mobile' not in resp_data or not resp_data['mobile']:
                logger.error(f"获取手机号失败: {resp_data}")
                if attempt < Config.MAX_RETRIES - 1:
                    time.sleep(Config.RETRY_DELAY)
                continue

            logger.info(f"成功获取手机号: {resp_data['mobile']}")
            return resp_data['mobile']

        except (RequestException, ConnectionError, Timeout) as e:
            logger.error(f"获取手机号请求出错 (尝试 {attempt + 1}/{Config.MAX_RETRIES}): {e}")
            if attempt < Config.MAX_RETRIES - 1:
                time.sleep(Config.RETRY_DELAY)
        except (ValueError, KeyError) as e:
            logger.error(f"获取手机号结果解析错误: {e}")
            if attempt < Config.MAX_RETRIES - 1:
                time.sleep(Config.RETRY_DELAY)

    logger.error("获取手机号失败，已达到最大重试次数")
    return None


def yezi_code(token, pid, phone):
    if not token or not phone:
        logger.error("获取验证码失败: token或phone无效")
        return None

    end_time = time.time() + Config.SMS_WAIT_TIME

    while time.time() < end_time:
        try:
            logger.info(f"正在获取手机号 {phone} 的验证码...")
            resp = requests.get(
                f'http://api.sqhyw.net:90/api/get_message?token={token}&project_id={pid}&phone_num={phone}',
                timeout=Config.REQUEST_TIMEOUT
            )

            if resp.status_code != 200:
                logger.error(f"获取验证码失败，状态码: {resp.status_code}")
                time.sleep(Config.SMS_CHECK_INTERVAL)
                continue

            resp_data = resp.json()
            logger.debug(f"获取验证码结果: {resp_data}")

            if resp_data.get('code'):
                logger.info(f"成功获取验证码: {resp_data['code']}")
                return resp_data['code']

            # 尝试从data中提取验证码
            if 'data' in resp_data and len(resp_data['data']) > 0:
                for msg in resp_data['data']:
                    if 'content' in msg and msg['content']:
                        # 提取验证码逻辑可以在这里增强
                        logger.info(f"从消息内容中提取验证码: {msg['content']}")
                        return resp_data.get('code', '')

            logger.info(f"验证码还未收到，等待 {Config.SMS_CHECK_INTERVAL} 秒后重试...")
            time.sleep(Config.SMS_CHECK_INTERVAL)

        except (RequestException, ConnectionError, Timeout) as e:
            logger.error(f"获取验证码请求出错: {e}")
            time.sleep(Config.SMS_CHECK_INTERVAL)
        except (ValueError, KeyError) as e:
            logger.error(f"获取验证码结果解析错误: {e}")
            time.sleep(Config.SMS_CHECK_INTERVAL)

    logger.error(f"获取验证码失败: 超过最大等待时间 {Config.SMS_WAIT_TIME} 秒")
    return None


# ================== 硅基流动操作
def sms(phone, result):
    if not phone or not result:
        logger.error("发送短信验证失败: 手机号或验证码结果无效")
        return False

    try:
        result_data = json.loads(result['code'] if isinstance(result, dict) else result)

        params = {
            "phone": phone,
            "area": "+86",
            "device": "a1fda524fe1d09e646be0fe95f541972",
            "captcha_id": "592ad182314270f0c1442d9aa82d3ac2",
            "lot_number": str(result_data['lot_number']),
            "pass_token": str(result_data['pass_token']),
            "gen_time": str(result_data['gen_time']),
            "captcha_output": str(result_data['captcha_output'])
        }

        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        logger.info(f"正在向手机 {phone} 发送验证码...")
        resp = requests.post(
            'https://account.siliconflow.cn/api/open/sms',
            data=json.dumps(params),
            headers=headers,
            timeout=Config.REQUEST_TIMEOUT
        )

        if resp.status_code != 200:
            logger.error(f"发送验证码失败，状态码: {resp.status_code}")
            return False

        resp_data = resp.json()
        logger.debug(f"发送验证码结果: {resp_data}")

        if resp_data.get('status'):
            logger.info("验证码发送成功")
            return True
        else:
            logger.error(f"发送验证码失败: {resp_data}")
            return False

    except (RequestException, ConnectionError, Timeout) as e:
        logger.error(f"发送验证码请求出错: {e}")
        return False
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        logger.error(f"发送验证码数据处理错误: {e}")
        return False


def login(phone, code, share_code):
    if not phone or not code:
        logger.error("登录失败: 手机号或验证码无效")
        return None

    try:
        params = {
            "phone": phone,
            "code": code,
            "shareCode": share_code,
            "area": "+86"
        }

        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        logger.info(f"正在使用手机 {phone} 和验证码 {code} 登录...")
        resp = requests.post(
            'https://account.siliconflow.cn/api/open/account/user',
            data=json.dumps(params),
            headers=headers,
            timeout=Config.REQUEST_TIMEOUT
        )

        if resp.status_code != 200:
            logger.error(f"登录失败，状态码: {resp.status_code}")
            return None

        session_token = resp.cookies.get('__SF_auth.session-token')

        if not session_token:
            logger.error("登录失败: 未获取到会话令牌")
            return None

        logger.info(f"登录成功，获取到会话令牌")
        return session_token

    except (RequestException, ConnectionError, Timeout) as e:
        logger.error(f"登录请求出错: {e}")
        return None
    except Exception as e:
        logger.error(f"登录过程发生错误: {e}")
        return None


def get_ak(ck):
    if not ck:
        logger.error("获取API密钥失败: 会话令牌无效")
        return None

    try:
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Cookie': f'__SF_auth.session-token={ck}'
        }

        logger.info("正在获取API密钥...")
        resp = requests.post(
            'https://cloud.siliconflow.cn/api/redirect/apikey?action=create',
            data=json.dumps({"description": "LinuxDo"}),
            headers=headers,
            timeout=Config.REQUEST_TIMEOUT
        )

        if resp.status_code != 200:
            logger.error(f"获取API密钥失败，状态码: {resp.status_code}")
            return None

        resp_data = resp.json()
        logger.debug(f"获取API密钥结果: {resp_data}")

        if 'data' in resp_data and 'secretKey' in resp_data['data']:
            secret_key = resp_data['data']['secretKey']
            logger.info("成功获取API密钥")
            return secret_key
        else:
            logger.error(f"获取API密钥失败，响应数据不符合预期: {resp_data}")
            return None

    except (RequestException, ConnectionError, Timeout) as e:
        logger.error(f"获取API密钥请求出错: {e}")
        return None
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        logger.error(f"获取API密钥数据处理错误: {e}")
        return None


def worker(token, thread_id, stop_event):
    account_count = 0

    while not stop_event.is_set() and account_count < Config.MAX_ACCOUNTS_PER_THREAD:
        try:
            logger.info(f"线程 {thread_id}: 开始第 {account_count + 1} 个账号的注册流程")

            # 添加随机延迟减轻服务器压力并避免被封
            delay = random.uniform(Config.RATE_LIMIT_DELAY[0], Config.RATE_LIMIT_DELAY[1])
            time.sleep(delay)

            # 获取手机号
            phone = yezi_mobile(token, Config.PID)
            if not phone:
                logger.error(f"线程 {thread_id}: 获取手机号失败，跳过此次注册")
                continue

            # 解决验证码
            captcha_result = solve_geetest_v4()
            if not captcha_result:
                logger.error(f"线程 {thread_id}: 验证码解决失败，跳过此次注册")
                continue

            # 发送短信验证码
            if not sms(phone, captcha_result):
                logger.error(f"线程 {thread_id}: 发送验证码失败，跳过此次注册")
                continue

            # 获取短信验证码
            code = yezi_code(token, Config.PID, phone)
            if not code:
                logger.error(f"线程 {thread_id}: 获取验证码失败，跳过此次注册")
                continue

            # 登录/注册账号
            ck = login(phone, code, Config.SHARE_CODE)
            if not ck:
                logger.error(f"线程 {thread_id}: 注册账号失败，跳过此次注册")
                continue

            # 获取API密钥
            ak = get_ak(ck)
            if not ak:
                logger.error(f"线程 {thread_id}: 获取API密钥失败，跳过此次注册")
                continue

            # 保存API密钥
            logger.info(f"线程 {thread_id}: 成功获取新API密钥")
            with open(Config.OUTPUT_FILE, 'a') as f:
                f.write(f"{ak}\n")

            account_count += 1
            logger.info(f"线程 {thread_id}: 完成第 {account_count}/{Config.MAX_ACCOUNTS_PER_THREAD} 个账号的注册")

        except Exception as e:
            logger.error(f"线程 {thread_id}: 注册过程发生未处理的错误: {e}")
            time.sleep(Config.RETRY_DELAY)  # 出错后暂停一会

    logger.info(f"线程 {thread_id}: {'被中止' if stop_event.is_set() else '已完成配额'}")


def main():
    try:
        logger.info("=" * 50)
        logger.info("开始执行注册脚本")
        logger.info("=" * 50)

        # 确保输出文件目录存在
        output_dir = os.path.dirname(Config.OUTPUT_FILE)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # 登录接码平台
        token = yezi_login(Config.USERNAME, Config.PASSWORD)
        if not token:
            logger.error("程序终止: 无法登录接码平台")
            return

        # 创建停止事件
        stop_event = threading.Event()

        try:
            # 创建并启动工作线程
            threads = []
            for i in range(Config.THREAD_COUNT):
                thread = threading.Thread(
                    target=worker,
                    kwargs={
                        'token': token,
                        'thread_id': i + 1,
                        'stop_event': stop_event
                    }
                )
                thread.daemon = True  # 设为守护线程，主线程结束时会终止
                thread.start()
                threads.append(thread)
                logger.info(f"线程 {i + 1} 已启动")

            # 等待所有线程完成
            for thread in threads:
                thread.join()

        except KeyboardInterrupt:
            logger.info("检测到键盘中断，正在停止所有线程...")
            stop_event.set()  # 发送停止信号

            # 等待所有线程完成
            for thread in threads:
                thread.join(timeout=5.0)  # 给每个线程5秒时间优雅退出

            logger.info("所有线程已停止")

    except Exception as e:
        logger.error(f"主程序发生错误: {e}")

    logger.info("=" * 50)
    logger.info("注册脚本执行完毕")
    logger.info("=" * 50)


if __name__ == "__main__":
    main()
