#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动化漏洞扫描脚本
使用: python automate_scan.py target.com
"""

import subprocess
import json
import os
import sys
import sqlite3
import time
from datetime import datetime
from urllib.parse import urlparse

class AutomatedScanner:
    def __init__(self, domain):
        self.domain = domain
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = f"scans/{self.domain}_{self.timestamp}"
        self.subdomains_file = f"{self.output_dir}/subdomains.txt"
        self.alive_domains_file = f"{self.output_dir}/alive_domains.json"
        self.nuclei_results_file = f"{self.output_dir}/nuclei_results.json"
        self.db_file = f"{self.output_dir}/scan_results.db"
       
        # 创建输出目录
        os.makedirs(self.output_dir, exist_ok=True)
       
        # 初始化数据库
        self.init_database()
   
    def init_database(self):
        """初始化数据库和表结构"""
        self.conn = sqlite3.connect(self.db_file)
        self.cursor = self.conn.cursor()
       
        # 创建扫描会话表
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                start_time DATETIME NOT NULL,
                end_time DATETIME,
                status TEXT DEFAULT 'running',
                subdomain_count INTEGER DEFAULT 0,
                alive_domain_count INTEGER DEFAULT 0,
                vulnerability_count INTEGER DEFAULT 0
            )
        ''')
       
        # 创建子域名表
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_session_id INTEGER,
                subdomain TEXT NOT NULL,
                discovered_at DATETIME NOT NULL,
                FOREIGN KEY (scan_session_id) REFERENCES scan_sessions (id)
            )
        ''')
       
        # 创建存活域名表
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS alive_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_session_id INTEGER,
                subdomain_id INTEGER,
                url TEXT NOT NULL,
                status_code INTEGER,
                title TEXT,
                content_length INTEGER,
                technology TEXT,
                discovered_at DATETIME NOT NULL,
                FOREIGN KEY (scan_session_id) REFERENCES scan_sessions (id),
                FOREIGN KEY (subdomain_id) REFERENCES subdomains (id)
            )
        ''')
       
        # 创建漏洞表
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_session_id INTEGER,
                alive_domain_id INTEGER,
                template_id TEXT,
                template_name TEXT,
                template_url TEXT,
                template_tags TEXT,
                host TEXT NOT NULL,
                matched_at TEXT,
                severity TEXT,
                description TEXT,
                reference TEXT,
                extracted_results TEXT,
                curl_command TEXT,
                timestamp DATETIME NOT NULL,
                FOREIGN KEY (scan_session_id) REFERENCES scan_sessions (id),
                FOREIGN KEY (alive_domain_id) REFERENCES alive_domains (id)
            )
        ''')
       
        # 插入扫描会话记录
        self.cursor.execute(
            "INSERT INTO scan_sessions (domain, start_time) VALUES (?, ?)",
            (self.domain, datetime.now().isoformat())
        )
        self.scan_session_id = self.cursor.lastrowid
        self.conn.commit()
       
        print(f"[+] 数据库初始化完成，扫描会话ID: {self.scan_session_id}")
   
    def run_command(self, cmd, description):
        """执行命令并处理输出"""
        print(f"[+] {description}")
        print(f"    Command: {cmd}")
       
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=3600  # 1小时超时
            )
           
            if result.returncode == 0:
                print("    ✅ 成功完成")
                return result.stdout
            else:
                print(f"    ❌ 失败: {result.stderr}")
                return None
               
        except subprocess.TimeoutExpired:
            print("    ⏰ 命令执行超时")
            return None
        except Exception as e:
            print(f"    ❌ 异常: {str(e)}")
            return None
   
    def find_subdomains(self):
        """使用 Subfinder 发现子域名"""
        cmd = f"subfinder -d {self.domain} -silent -o {self.subdomains_file}"
        output = self.run_command(cmd, "使用 Subfinder 发现子域名")
       
        # 读取并存储发现的子域名
        if os.path.exists(self.subdomains_file):
            with open(self.subdomains_file, 'r') as f:
                subdomains = [line.strip() for line in f.readlines() if line.strip()]
           
            subdomain_count = len(subdomains)
           
            # 存储到数据库
            for subdomain in subdomains:
                self.cursor.execute(
                    "INSERT INTO subdomains (scan_session_id, subdomain, discovered_at) VALUES (?, ?, ?)",
                    (self.scan_session_id, subdomain, datetime.now().isoformat())
                )
           
            # 更新扫描会话统计
            self.cursor.execute(
                "UPDATE scan_sessions SET subdomain_count = ? WHERE id = ?",
                (subdomain_count, self.scan_session_id)
            )
            self.conn.commit()
           
            print(f"    发现 {subdomain_count} 个子域名并存储到数据库")
   
    def probe_http(self):
        """使用 HTTPX 探测存活的域名"""
        cmd = f"httpx -l {self.subdomains_file} -status-code -title -content-length -tech-detect -json -silent -o {self.alive_domains_file}"
        output = self.run_command(cmd, "使用 HTTPX 探测存活的域名")
       
        # 读取并存储存活的域名
        if os.path.exists(self.alive_domains_file):
            alive_count = 0
           
            with open(self.alive_domains_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        alive_count += 1
                       
                        # 获取对应的子域名ID
                        url_host = urlparse(data.get("url", "")).hostname
                        self.cursor.execute(
                            "SELECT id FROM subdomains WHERE subdomain = ? AND scan_session_id = ?",
                            (url_host, self.scan_session_id)
                        )
                        subdomain_result = self.cursor.fetchone()
                        subdomain_id = subdomain_result[0] if subdomain_result else None
                       
                        # 存储到数据库
                        self.cursor.execute(
                            """INSERT INTO alive_domains
                            (scan_session_id, subdomain_id, url, status_code, title, content_length, technology, discovered_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                self.scan_session_id,
                                subdomain_id,
                                data.get("url", ""),
                                data.get("status_code", 0),
                                data.get("title", ""),
                                data.get("content_length", 0),
                                ",".join(data.get("tech", [])) if data.get("tech") else None,
                                datetime.now().isoformat()
                            )
                        )
                    except (json.JSONDecodeError, KeyError) as e:
                        print(f"    解析错误: {str(e)}")
           
            # 更新扫描会话统计
            self.cursor.execute(
                "UPDATE scan_sessions SET alive_domain_count = ? WHERE id = ?",
                (alive_count, self.scan_session_id)
            )
            self.conn.commit()
           
            print(f"    发现 {alive_count} 个存活的域名并存储到数据库")
           
            # 创建纯URL列表供Nuclei使用
            urls_file = f"{self.output_dir}/urls.txt"
            with open(urls_file, 'w') as out_f:
                with open(self.alive_domains_file, 'r') as in_f:
                    for line in in_f:
                        try:
                            data = json.loads(line.strip())
                            out_f.write(data.get("url", "") + "\n")
                        except json.JSONDecodeError:
                            continue
   
    def run_nuclei_scan(self):
        """使用 Nuclei 进行漏洞扫描"""
        urls_file = f"{self.output_dir}/urls.txt"
        cmd = f"nuclei -l {urls_file} -proxy-url http://127.0.0.1:8080 -json -o {self.nuclei_results_file}"
        output = self.run_command(cmd, "使用 Nuclei 进行漏洞扫描 (通过 Burp 代理)")
       
        # 解析并存储扫描结果
        if os.path.exists(self.nuclei_results_file):
            vuln_count = 0
            severity_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
           
            with open(self.nuclei_results_file, 'r') as f:
                for line in f:
                    try:
                        result = json.loads(line.strip())
                        vuln_count += 1
                        severity = result.get("info", {}).get("severity", "").lower()
                       
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                       
                        # 获取对应的存活域名ID
                        host = result.get("host", "")
                        self.cursor.execute(
                            "SELECT id FROM alive_domains WHERE url = ? AND scan_session_id = ?",
                            (host, self.scan_session_id)
                        )
                        alive_domain_result = self.cursor.fetchone()
                        alive_domain_id = alive_domain_result[0] if alive_domain_result else None
                       
                        # 存储漏洞信息到数据库
                        info = result.get("info", {})
                        self.cursor.execute(
                            """INSERT INTO vulnerabilities
                            (scan_session_id, alive_domain_id, template_id, template_name, template_url,
                            template_tags, host, matched_at, severity, description, reference,
                            extracted_results, curl_command, timestamp)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                self.scan_session_id,
                                alive_domain_id,
                                result.get("templateID", ""),
                                info.get("name", ""),
                                result.get("template", ""),
                                ",".join(info.get("tags", [])) if info.get("tags") else None,
                                host,
                                result.get("matched-at", ""),
                                info.get("severity", ""),
                                info.get("description", ""),
                                ",".join(info.get("reference", [])) if info.get("reference") else None,
                                ",".join(result.get("extracted-results", [])) if result.get("extracted-results") else None,
                                result.get("curl-command", ""),
                                datetime.now().isoformat()
                            )
                        )
                       
                        # 显示高危漏洞
                        if severity in ["high", "critical"]:
                            print(f"    ⚠️  发现高危漏洞: {info.get('name', '')}")
                            print(f"       目标: {host}")
                            print(f"       严重性: {severity}")
                           
                    except (json.JSONDecodeError, KeyError) as e:
                        print(f"    解析错误: {str(e)}")
           
            # 更新扫描会话统计
            self.cursor.execute(
                "UPDATE scan_sessions SET vulnerability_count = ?, status = 'completed', end_time = ? WHERE id = ?",
                (vuln_count, datetime.now().isoformat(), self.scan_session_id)
            )
            self.conn.commit()
           
            print(f"    📊 扫描完成: 共发现 {vuln_count} 个漏洞")
            print(f"       严重程度分布: {severity_counts}")
   
    def generate_report(self):
        """生成扫描报告"""
        report_file = f"{self.output_dir}/scan_report.md"
       
        # 从数据库获取统计信息
        self.cursor.execute(
            "SELECT subdomain_count, alive_domain_count, vulnerability_count FROM scan_sessions WHERE id = ?",
            (self.scan_session_id,)
        )
        stats = self.cursor.fetchone()
       
        # 获取漏洞按严重性分类统计
        severity_stats = {}
        self.cursor.execute(
            "SELECT severity, COUNT(*) FROM vulnerabilities WHERE scan_session_id = ? GROUP BY severity",
            (self.scan_session_id,)
        )
        for row in self.cursor.fetchall():
            severity_stats[row[0]] = row[1]
       
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# 安全扫描报告\n")
            f.write(f"**目标域名**: {self.domain}\n")
            f.write(f"**扫描时间**: {datetime.now()}\n")
            f.write(f"**扫描会话ID**: {self.scan_session_id}\n\n")
           
            # 统计摘要
            f.write("## 扫描统计摘要\n")
            f.write(f"- 发现子域名: {stats[0]}\n")
            f.write(f"- 存活域名: {stats[1]}\n")
            f.write(f"- 发现漏洞: {stats[2]}\n\n")
           
            # 漏洞严重性分布
            f.write("### 漏洞严重性分布\n")
            for severity, count in severity_stats.items():
                f.write(f"- {severity.capitalize()}: {count}\n")
            f.write("\n")
           
            # 高危漏洞列表
            f.write("## 高危漏洞列表\n")
            self.cursor.execute(
                """SELECT v.template_name, v.host, v.severity, v.description, a.url
                FROM vulnerabilities v
                JOIN alive_domains a ON v.alive_domain_id = a.id
                WHERE v.scan_session_id = ? AND v.severity IN ('high', 'critical')
                ORDER BY v.severity DESC""",
                (self.scan_session_id,)
            )
            high_vulns = self.cursor.fetchall()
           
            if not high_vulns:
                f.write("未发现高危漏洞\n")
            else:
                for vuln in high_vulns:
                    f.write(f"### {vuln[0]}\n")
                    f.write(f"- **目标**: {vuln[1]}\n")
                    f.write(f"- **严重性**: {vuln[2]}\n")
                    f.write(f"- **描述**: {vuln[3]}\n")
                    f.write(f"- **URL**: {vuln[4]}\n\n")
           
            # 所有漏洞列表
            f.write("## 所有漏洞列表\n")
            self.cursor.execute(
                """SELECT v.template_name, v.host, v.severity, v.description, a.url
                FROM vulnerabilities v
                JOIN alive_domains a ON v.alive_domain_id = a.id
                WHERE v.scan_session_id = ?
                ORDER BY v.severity DESC, v.template_name""",
                (self.scan_session_id,)
            )
            all_vulns = self.cursor.fetchall()
           
            for vuln in all_vulns:
                f.write(f"### {vuln[0]}\n")
                f.write(f"- **目标**: {vuln[1]}\n")
                f.write(f"- **严重性**: {vuln[2]}\n")
                f.write(f"- **描述**: {vuln[3]}\n")
                f.write(f"- **URL**: {vuln[4]}\n\n")
       
        print(f"[+] 报告已生成: {report_file}")
   
    def query_examples(self):
        """数据库查询示例"""
        print("\n[+] 数据库查询示例:")
       
        # 示例1: 获取所有高危漏洞
        print("1. 高危漏洞列表:")
        self.cursor.execute(
            """SELECT template_name, host, severity FROM vulnerabilities
            WHERE scan_session_id = ? AND severity IN ('high', 'critical')""",
            (self.scan_session_id,)
        )
        high_vulns = self.cursor.fetchall()
       
        for vuln in high_vulns:
            print(f"   - {vuln[0]} @ {vuln[1]} ({vuln[2]})")
       
        # 示例2: 获取使用特定技术的域名
        print("\n2. 使用特定技术的域名:")
        self.cursor.execute(
            """SELECT url, technology FROM alive_domains
            WHERE scan_session_id = ? AND technology LIKE '%wordpress%'""",
            (self.scan_session_id,)
        )
        tech_domains = self.cursor.fetchall()
       
        for domain in tech_domains:
            print(f"   - {domain[0]} ({domain[1]})")
       
        # 示例3: 统计各模板发现的漏洞数量
        print("\n3. 各漏洞模板统计:")
        self.cursor.execute(
            """SELECT template_name, COUNT(*) as count FROM vulnerabilities
            WHERE scan_session_id = ? GROUP BY template_name ORDER BY count DESC""",
            (self.scan_session_id,)
        )
        template_stats = self.cursor.fetchall()
       
        for stat in template_stats:
            print(f"   - {stat[0]}: {stat[1]}")
   
    def run_full_scan(self):
        """执行完整扫描流程"""
        print(f"🔍 开始对 {self.domain} 进行自动化安全扫描")
        print("=" * 60)
       
        self.find_subdomains()
        self.probe_http()
        self.run_nuclei_scan()
        self.generate_report()
        self.query_examples()
       
        # 关闭数据库连接
        self.conn.close()
       
        print("")
        print(f"✅ 扫描完成! 结果保存在 {self.output_dir} 目录中")
        print(f"   数据库文件: {self.db_file}")

def main():
    if len(sys.argv) != 2:
        print(f"使用方法: {sys.argv[0]} <域名>")
        sys.exit(1)
   
    domain = sys.argv[1]
    scanner = AutomatedScanner(domain)
    scanner.run_full_scan()

if __name__ == "__main__":
    main()