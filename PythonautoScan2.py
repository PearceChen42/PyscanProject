#!/usr/bin/env python3
"""
自动化网络安全扫描脚本
集成: Naabu, Amass, HTTPX, Nuclei, 和 Burp Suite
作者: PearceChen
日期: 2025
"""

import subprocess
import json
import os
import sys
import time
import argparse
from datetime import datetime
from pathlib import Path


class AutomatedScanner:
    def __init__(self, domain, output_dir=None):
        self.domain = domain
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
       
        # 设置输出目录
        if output_dir:
            self.output_dir = Path(output_dir) / f"{self.domain}_{self.timestamp}"
        else:
            self.output_dir = Path(f"scans/{self.domain}_{self.timestamp}")
           
        self.output_dir.mkdir(parents=True, exist_ok=True)
       
        # 初始化结果文件路径
        self.amass_results = self.output_dir / "amass_subdomains.txt"
        self.naabu_results = self.output_dir / "naabu_ports.txt"
        self.httpx_results = self.output_dir / "httpx_urls.txt"
        self.nuclei_results = self.output_dir / "nuclei_vulns.txt"
        self.burp_targets = self.output_dir / "burp_targets.txt"
       
        print(f"[*] 扫描结果将保存到: {self.output_dir}")

    def run_command(self, command, description, output_file=None):
        """运行命令行工具并处理输出"""
        print(f"[+] {description}")
        print(f" 命令: {command}")
       
        try:
            if output_file:
                with open(output_file, 'w') as f:
                    process = subprocess.Popen(
                        command,
                        shell=True,
                        stdout=f,
                        stderr=subprocess.PIPE,
                        text=True
                    )
            else:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
           
            stdout, stderr = process.communicate()
           
            if process.returncode != 0:
                print(f"[-] 错误: {stderr}")
                return False
               
            return True
           
        except Exception as e:
            print(f"[-] 执行命令时出错: {e}")
            return False

    def run_amass(self):
        """使用Amass进行子域名枚举"""
        command = f"amass enum -d {self.domain} -o {self.amass_results}"
        success = self.run_command(command, "运行Amass进行子域名枚举", self.amass_results)
       
        if success and os.path.exists(self.amass_results) and os.path.getsize(self.amass_results) > 0:
            subdomain_count = len(open(self.amass_results).readlines())
            print(f"[+] Amass完成，发现 {subdomain_count} 个子域名")
            return True
        else:
            print("[-] Amass未发现子域名或执行失败")
            return False

    def run_naabu(self):
        """使用Naabu进行端口扫描"""
        if not os.path.exists(self.amass_results):
            print("[-] 未找到Amass结果，无法进行端口扫描")
            return False
           
        command = f"naabu -list {self.amass_results} -o {self.naabu_results}"
        success = self.run_command(command, "运行Naabu进行端口扫描", self.naabu_results)
       
        if success and os.path.exists(self.naabu_results) and os.path.getsize(self.naabu_results) > 0:
            port_count = len(open(self.naabu_results).readlines())
            print(f"[+] Naabu完成，发现 {port_count} 个开放端口")
            return True
        else:
            print("[-] Naabu未发现开放端口或执行失败")
            return False

    def run_httpx(self):
        """使用HTTPX发现HTTP服务"""
        if not os.path.exists(self.naabu_results):
            print("[-] 未找到Naabu结果，无法进行HTTP发现")
            return False
           
        command = f"httpx -list {self.naabu_results} -o {self.httpx_results} -title -status-code -tech-detect"
        success = self.run_command(command, "运行HTTPX进行HTTP服务发现", self.httpx_results)
       
        if success and os.path.exists(self.httpx_results) and os.path.getsize(self.httpx_results) > 0:
            url_count = len(open(self.httpx_results).readlines())
            print(f"[+] HTTPX完成，发现 {url_count} 个HTTP服务")
            return True
        else:
            print("[-] HTTPX未发现HTTP服务或执行失败")
            return False

    def run_nuclei(self):
        """使用Nuclei进行漏洞扫描"""
        if not os.path.exists(self.httpx_results):
            print("[-] 未找到HTTPX结果，无法进行漏洞扫描")
            return False
           
        command = f"nuclei -l {self.httpx_results} -t cves/ -t vulnerabilities/ -o {self.nuclei_results}"
        success = self.run_command(command, "运行Nuclei进行漏洞扫描", self.nuclei_results)
       
        if success and os.path.exists(self.nuclei_results):
            if os.path.getsize(self.nuclei_results) > 0:
                vuln_count = len(open(self.nuclei_results).readlines())
                print(f"[+] Nuclei完成，发现 {vuln_count} 个潜在漏洞")
            else:
                print("[+] Nuclei完成，未发现漏洞")
            return True
        else:
            print("[-] Nuclei执行失败")
            return False

    def prepare_burp_targets(self):
        """准备Burp Suite目标文件"""
        if not os.path.exists(self.httpx_results):
            print("[-] 未找到HTTPX结果，无法准备Burp目标")
            return False
           
        # 从HTTPX结果中提取URL
        urls = set()
        with open(self.httpx_results, 'r') as f:
            for line in f:
                if line.strip():
                    # 假设HTTPX输出是JSON格式
                    try:
                        data = json.loads(line.strip())
                        if 'url' in data:
                            urls.add(data['url'])
                    except json.JSONDecodeError:
                        # 如果不是JSON，可能是纯URL列表
                        urls.add(line.strip())
       
        # 写入Burp兼容的目标文件
        with open(self.burp_targets, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
               
        print(f"[+] Burp目标文件已准备: {self.burp_targets}")
        return True

    def generate_report(self):
        """生成扫描报告"""
        report_file = self.output_dir / "scan_report.md"
       
        # 收集统计信息
        subdomain_count = 0
        if os.path.exists(self.amass_results):
            with open(self.amass_results, 'r') as f:
                subdomain_count = len(f.readlines())
               
        url_count = 0
        if os.path.exists(self.httpx_results):
            with open(self.httpx_results, 'r') as f:
                url_count = len(f.readlines())
               
        vuln_count = 0
        vulns = []
        if os.path.exists(self.nuclei_results):
            with open(self.nuclei_results, 'r') as f:
                vulns = f.readlines()
                vuln_count = len(vulns)
       
        # 生成报告内容
        report_content = f"""# 安全扫描报告: {self.domain}

## 扫描概览
- 扫描时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- 目标域名: {self.domain}
- 发现子域名: {subdomain_count}
- 发现HTTP服务: {url_count}
- 发现漏洞: {vuln_count}

## 扫描详情

### 1. 子域名发现 (Amass)
Amass发现的子域名列表:

```

{open(self.amass_results).read() if os.path.exists(self.amass_results) else "无结果"}

```

### 2. 端口扫描结果 (Naabu)
Naabu发现的开放端口:

```

{open(self.naabu_results).read() if os.path.exists(self.naabu_results) else "无结果"}

```

### 3. HTTP服务发现 (HTTPX)
HTTPX发现的活跃HTTP服务:

```

{open(self.httpx_results).read() if os.path.exists(self.httpx_results) else "无结果"}

```

### 4. 漏洞扫描结果 (Nuclei)
Nuclei发现的潜在漏洞:

```

{"".join(vulns) if vulns else "未发现漏洞"}

```

## 后续步骤建议
1. 使用Burp Suite Professional导入 `{self.burp_targets}` 进行深入测试
2. 手动验证所有发现的潜在漏洞
3. 检查敏感信息泄露
4. 进行身份验证和授权测试

---
*报告生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*
"""
       
        with open(report_file, 'w') as f:
            f.write(report_content)
           
        print(f"[+] 扫描报告已生成: {report_file}")
        return True

    def run_full_scan(self):
        """执行完整扫描流程"""
        print(f"[*] 开始对 {self.domain} 进行自动化扫描")
       
        # 记录开始时间
        start_time = time.time()
       
        # 执行扫描步骤
        steps = [
            ("子域名枚举", self.run_amass),
            ("端口扫描", self.run_naabu),
            ("HTTP服务发现", self.run_httpx),
            ("漏洞扫描", self.run_nuclei),
            ("准备Burp目标", self.prepare_burp_targets),
            ("生成报告", self.generate_report)
        ]
       
        results = []
        for step_name, step_func in steps:
            step_start = time.time()
            result = step_func()
            step_time = time.time() - step_start
            results.append((step_name, result, step_time))
           
            if not result and step_name in ["子域名枚举", "端口扫描", "HTTP服务发现"]:
                print(f"[-] {step_name}失败，中止扫描")
                break
       
        # 计算总时间
        total_time = time.time() - start_time
       
        # 输出摘要
        print("\n" + "="*50)
        print("扫描摘要:")
        print("="*50)
        for step_name, success, step_time in results:
            status = "成功" if success else "失败"
            print(f"{step_name:.<20} {status} (耗时: {step_time:.2f}秒)")
       
        print(f"{'总耗时':.<20} {total_time:.2f}秒")
        print(f"结果目录: {self.output_dir}")
        print("="*50)
       
        # 提示Burp Suite使用
        if os.path.exists(self.burp_targets):
            print("\n[!] 请使用Burp Suite Professional导入以下文件进行深入测试:")
            print(f" {self.burp_targets}")

def main():
    parser = argparse.ArgumentParser(description="自动化网络安全扫描脚本")
    parser.add_argument("domain", help="要扫描的目标域名")
    parser.add_argument("-o", "--output", help="指定输出目录")
   
    args = parser.parse_args()
   
    if not args.domain:
        parser.print_help()
        sys.exit(1)
   
    # 创建扫描器实例并运行扫描
    scanner = AutomatedScanner(args.domain, args.output)
    scanner.run_full_scan()

if __name__ == "__main__":
    main()