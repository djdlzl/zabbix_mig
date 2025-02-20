import csv
import logging
import requests
import json
from config import ZABBIX_CREDENTIALS

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class ZabbixClient:
    def __init__(self):
        self.base_url = f"{ZABBIX_CREDENTIALS['url']}/api_jsonrpc.php"
        self.auth_token = None
        if 'token' in ZABBIX_CREDENTIALS:
            self.auth_token = ZABBIX_CREDENTIALS['token']
        elif all(k in ZABBIX_CREDENTIALS for k in ('user', 'password')):
            self.auth_token = self._login()
        else:
            raise Exception("Invalid Zabbix credentials provided")

    def _login(self):
        login_data = {
            "jsonrpc": "2.0",
            "method": "user.login",
            "params": {
                "user": ZABBIX_CREDENTIALS['user'],
                "password": ZABBIX_CREDENTIALS['password']
            },
            "id": 1
        }
        response = requests.post(self.base_url, json=login_data)
        result = response.json()
        if 'result' in result:
            logger.info("Successfully logged in to Zabbix API")
            return result['result']
        else:
            logger.error(f"Failed to login: {result['error']['data']}")
            raise Exception("Login failed")

    def _api_call(self, method, params):
        headers = {"Content-Type": "application/json-rpc"}
        if 'token' in ZABBIX_CREDENTIALS:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        data = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "auth": None if 'token' in ZABBIX_CREDENTIALS else self.auth_token,
            "id": 1
        }
        response = requests.post(self.base_url, json=data, headers=headers)
        result = response.json()
        if 'result' in result:
            return result['result']
        else:
            logger.error(f"API call failed: {result['error']['data']}")
            raise Exception(f"API call to {method} failed")
        

    def get_web_scenarios(self, host_name):
        """
        특정 호스트의 웹 시나리오 목록을 가져오는 메서드
        """
        host = self._api_call("host.get", {"filter": {"host": host_name}, "output": ["hostid"]})
        if not host:
            logger.error(f"Host {host_name} not found")
            return []
        host_id = host[0]["hostid"]

        web_scenarios = self._api_call("httptest.get", {
            "hostids": host_id,
            "output": ["httptestid", "name", "delay", "agent", "http_proxy", "steps"],
            "selectSteps": ["name", "url", "status_codes", "required"]
        })
        return web_scenarios

    def export_web_scenarios_and_triggers_to_csv(self, host_name, web_scenario_file, trigger_file):
        """
        특정 호스트의 웹 시나리오 및 트리거를 CSV 파일로 저장하는 메서드
        """
        web_scenarios = self.get_web_scenarios(host_name)
        if not web_scenarios:
            logger.warning(f"No web scenarios found for host: {host_name}")
            return

        with open(web_scenario_file, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["httptestid", "name", "delay", "agent", "http_proxy", "steps", "step_details"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for scenario in web_scenarios:
                steps_details = " | ".join([
                    f"{step['name']} ({step['url']} - {step['status_codes']} - {step['required']})"
                    for step in scenario.get("steps", [])
                ])
                writer.writerow({
                    "httptestid": scenario.get("httptestid", ""),
                    "name": scenario.get("name", ""),
                    "delay": scenario.get("delay", ""),
                    "agent": scenario.get("agent", ""),
                    "http_proxy": scenario.get("http_proxy", ""),
                    "steps": len(scenario.get("steps", [])),
                    "step_details": steps_details
                })
        
        with open(trigger_file, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["name", "problem_expression", "recovery_expression", "severity"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for scenario in web_scenarios:
                main_step = scenario.get("steps", [{}])[0]  # 첫 번째 스텝을 대표 URL로 사용
                url = main_step.get("url", "Unknown URL")
                trigger_name = f"{scenario['name']} ({url})"
                problem_expression = (
                    f"(last(/{host_name}/web.test.error[{scenario['name']}],#1)<>\"\") "
                    f"and last(/{host_name}/web.test.fail[{scenario['name']}],#1)>=1"
                )
                writer.writerow({
                    "name": trigger_name,
                    "problem_expression": problem_expression,
                    "severity": 4  # 중증 장애
                })
        
        logger.info(f"Exported web scenarios to {web_scenario_file} and triggers to {trigger_file} for host {host_name}")

    def import_web_scenarios_from_csv(self, host_name, web_scenario_file):
        """
        CSV 파일을 읽어 Zabbix에 웹 시나리오 추가
        """
        host = self._api_call("host.get", {"filter": {"host": host_name}, "output": ["hostid"]})
        if not host:
            logger.error(f"Host {host_name} not found")
            return
        host_id = host[0]["hostid"]

        with open(web_scenario_file, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                steps = []
                for index, step in enumerate(row["step_details"].split(" | "), start=1):
                    if step:
                        step_parts = step.split(' (')
                        step_name = step_parts[0]
                        step_url = step_parts[1].split(' - ')[0]
                        steps.append({
                            "no": index,
                            "name": step_name,
                            "url": step_url,
                            "timeout": "30s"
                        })
                
                params = {
                    "name": row["name"],
                    "hostid": host_id,
                    "delay": row.get("delay", "60s"),
                    "retries": 5,
                    "agent": row.get("agent", "Mozilla/5.0"),
                    "steps": steps
                }
                self._api_call("httptest.create", params)
                logger.info(f"Added web scenario: {row['name']}")

    def import_triggers_from_csv(self, host_name, trigger_file):
        """
        CSV 파일을 읽어 Zabbix에 트리거 추가
        """
        host = self._api_call("host.get", {"filter": {"host": host_name}, "output": ["hostid"]})
        if not host:
            logger.error(f"Host {host_name} not found")
            return
        host_id = host[0]["hostid"]

        with open(trigger_file, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                params = {
                    "description": row["name"],
                    "expression": row["problem_expression"],
                    "priority": row["severity"]
                }
                self._api_call("trigger.create", params)
                logger.info(f"Added trigger: {row['name']}")


    def update_web_scenario_timeout(self, host_name, timeout="60s"):
        """
        특정 호스트의 모든 웹 시나리오의 타임아웃을 변경하는 메서드
        """
        host = self._api_call("host.get", {"filter": {"host": host_name}, "output": ["hostid"]})
        if not host:
            logger.error(f"Host {host_name} not found")
            return
        host_id = host[0]["hostid"]
        
        web_scenarios = self._api_call("httptest.get", {"hostids": host_id, "output": ["httptestid", "name", "steps"], "selectSteps": ["name", "url", "timeout"]})
        
        for scenario in web_scenarios:
            steps = scenario["steps"]
            for step in steps:
                step["timeout"] = timeout
            params = {
                "httptestid": scenario["httptestid"],
                "steps": steps,
                "delay": "1m"
            }
            self._api_call("httptest.update", params)
            logger.info(f"Updated timeout to {timeout} for web scenario: {scenario['name']}")
    
    def enable_manual_close_triggers(self, host_name):
        """
        특정 호스트의 모든 트리거에서 장애 클로즈를 수동으로 변경하는 메서드
        """
        triggers = self._api_call("trigger.get", {"host": host_name, "output": ["triggerid", "description", "manual_close"]})
        
        for trigger in triggers:
            params = {
                "triggerid": trigger["triggerid"],
                "manual_close": 1
            }
            self._api_call("trigger.update", params)
            logger.info(f"Enabled manual close for trigger: {trigger['description']}")


# 사용 예시
if __name__ == "__main__":
    zabbix_client = ZabbixClient()

################ export ####################
    # host_name = "iworks-4"
    # web_scenario_csv = host_name + "_web_scenarios.csv"
    # trigger_csv = host_name + "_triggers.csv"
    # zabbix_client.export_web_scenarios_and_triggers_to_csv(host_name, web_scenario_csv, trigger_csv)


################ import ####################
    # host_name = "iworks-4"
    # web_scenario_csv = "iworks-4_web_scenarios.csv"
    # trigger_csv = "iworks-4_triggers.csv"
    
    # zabbix_client.import_web_scenarios_from_csv(host_name, web_scenario_csv)
    # zabbix_client.import_triggers_from_csv(host_name, trigger_csv)
    
    
################ update ####################
    for i in range(1,5):
        host_name = "iworks-"+str(i)
        zabbix_client.update_web_scenario_timeout(host_name, "60s")
        zabbix_client.enable_manual_close_triggers(host_name)